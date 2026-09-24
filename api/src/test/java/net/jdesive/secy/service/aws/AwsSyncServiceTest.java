package net.jdesive.secy.service.aws;

import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.persistence.entity.SourceConnectorType;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.transaction.annotation.Transactional;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.Reservation;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ecr.EcrClient;
import software.amazon.awssdk.services.ecr.model.DescribeImagesRequest;
import software.amazon.awssdk.services.ecr.model.DescribeImagesResponse;
import software.amazon.awssdk.services.ecr.model.DescribeRepositoriesRequest;
import software.amazon.awssdk.services.ecr.model.DescribeRepositoriesResponse;
import software.amazon.awssdk.services.ecr.model.EcrException;
import software.amazon.awssdk.services.ecr.model.ImageDetail;
import software.amazon.awssdk.services.ecr.model.Repository;
import software.amazon.awssdk.services.inspector2.Inspector2Client;
import software.amazon.awssdk.services.inspector2.model.Finding;
import software.amazon.awssdk.services.inspector2.model.FixAvailable;
import software.amazon.awssdk.services.inspector2.model.ListFindingsRequest;
import software.amazon.awssdk.services.inspector2.model.ListFindingsResponse;
import software.amazon.awssdk.services.inspector2.model.PackageManager;
import software.amazon.awssdk.services.inspector2.model.PackageVulnerabilityDetails;
import software.amazon.awssdk.services.inspector2.model.VulnerablePackage;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.FunctionConfiguration;
import software.amazon.awssdk.services.lambda.model.LambdaException;
import software.amazon.awssdk.services.lambda.model.ListFunctionsRequest;
import software.amazon.awssdk.services.lambda.model.ListFunctionsResponse;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link AwsSyncService} against Mockito doubles of the four AWS SDK clients — no live AWS
 * credentials or network access, per {@link AwsClientFactory}'s Javadoc on why the client
 * construction seam exists. Persistence (asset creation, component upsert, alert correlation) is the
 * real path through a real {@code AssetService} against the H2 test database, so these also prove the
 * Inspector-to-{@code ScannedPackage}/{@code ScannerFinding} mapping actually lands correctly-shaped
 * rows, not just that the right methods were called.
 */
@SpringBootTest
class AwsSyncServiceTest {

    @Autowired
    private AwsSyncService awsSyncService;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @MockBean
    private AwsClientFactory awsClientFactory;

    private Ec2Client ec2;
    private EcrClient ecr;
    private LambdaClient lambda;
    private Inspector2Client inspector;

    private void wireClients() {
        ec2 = mock(Ec2Client.class);
        ecr = mock(EcrClient.class);
        lambda = mock(LambdaClient.class);
        inspector = mock(Inspector2Client.class);
        when(awsClientFactory.ec2Client(any())).thenReturn(ec2);
        when(awsClientFactory.ecrClient(any())).thenReturn(ecr);
        when(awsClientFactory.lambdaClient(any())).thenReturn(lambda);
        when(awsClientFactory.inspector2Client(any())).thenReturn(inspector);
    }

    private static SourceConnector connector() {
        SourceConnector connector = new SourceConnector();
        connector.setType(SourceConnectorType.AWS);
        connector.setName("Test AWS connector");
        connector.setScope("us-east-1");
        return connector;
    }

    /* ------------------------------------------------------------------ */
    /* Mixed success: EC2 + ECR + Lambda, mixed fix states                */
    /* ------------------------------------------------------------------ */

    @Test
    @Transactional
    void ec2EcrAndLambdaAreEnumeratedAndTheirInspectorFindingsApplied() {
        wireClients();
        // Correlation only raises an alert for a CVE the NVD mirror already knows about (see
        // CorrelationService#reconcile) -- true for a scanner finding exactly as for OSV/CPE, so
        // these three must exist before the sync runs.
        seedCve("CVE-2024-1111");
        seedCve("CVE-2024-2222");
        seedCve("CVE-2024-3333");

        stubEc2Instances(Instance.builder().instanceId("i-1")
                .tags(Tag.builder().key("Name").value("web-1").build())
                .build());
        stubEcrRepositories(Repository.builder().repositoryName("app").build());
        stubEcrImages("app", ImageDetail.builder().repositoryName("app")
                .imageDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .imageTags("v1")
                .build());
        stubLambdaFunctions(FunctionConfiguration.builder().functionName("fn-1")
                .functionArn("arn:aws:lambda:us-east-1:123456789012:function:fn-1")
                .build());

        stubFindings(Map.of(
                "i-1", findingsOf(finding("CVE-2024-1111", FixAvailable.YES,
                        vulnPackage("lodash", "4.17.20", PackageManager.NPM, "4.17.21"))),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        findingsOf(finding("CVE-2024-2222", FixAvailable.NO,
                                vulnPackage("openssl", "1.1.1", PackageManager.OS, null))),
                "arn:aws:lambda:us-east-1:123456789012:function:fn-1",
                        findingsOf(finding("CVE-2024-3333", FixAvailable.PARTIAL,
                                vulnPackage("requests", "2.25.0", PackageManager.PYTHONPKG, "2.31.0")))));

        IngestResult result = awsSyncService.sync(connector(), JobProgress.NOOP);

        assertThat(result.itemsProcessed()).isEqualTo(3);

        Asset host = mustFindAsset(AssetType.HOST, "web-1");
        Asset image = mustFindAsset(AssetType.CONTAINER_IMAGE, "app:v1");
        Asset function = mustFindAsset(AssetType.SERVICE, "fn-1");

        VulnerabilityAlert fixedAlert = mustFindAlert(host.getId(), "CVE-2024-1111");
        assertThat(fixedAlert.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(fixedAlert.getFixedVersions()).isEqualTo("4.17.21");

        VulnerabilityAlert noFixAlert = mustFindAlert(image.getId(), "CVE-2024-2222");
        assertThat(noFixAlert.getFixState()).isEqualTo(FixState.NO_FIX);

        // PARTIAL at the finding level, but this specific package names its own fixed version --
        // that is a positive FIXED verdict for it regardless of the finding's overall fixAvailable.
        VulnerabilityAlert partialAlert = mustFindAlert(function.getId(), "CVE-2024-3333");
        assertThat(partialAlert.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(partialAlert.getFixedVersions()).isEqualTo("2.31.0");

        // OS packages get no PURL/ecosystem (same precedent as Trivy/Grype OS packages).
        assertThat(noFixAlert.getAssetComponent().getEcosystem()).isNull();
        assertThat(fixedAlert.getAssetComponent().getEcosystem()).isEqualTo("npm");
        assertThat(partialAlert.getAssetComponent().getEcosystem()).isEqualTo("PyPI");
    }

    /* ------------------------------------------------------------------ */
    /* Partial failure: one resource type down, others still succeed      */
    /* ------------------------------------------------------------------ */

    @Test
    @Transactional
    void aPermissionFailureOnOneResourceTypeDoesNotStopTheOthers() {
        wireClients();

        stubEc2Instances(Instance.builder().instanceId("i-1").build());
        stubEcrRepositories(Repository.builder().repositoryName("app").build());
        stubEcrImages("app", ImageDetail.builder().repositoryName("app")
                .imageDigest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .imageTags("v1")
                .build());
        when(lambda.listFunctions(any(ListFunctionsRequest.class)))
                .thenThrow(LambdaException.builder().message("Access Denied").statusCode(403).build());
        stubFindings(Map.of());

        IngestResult result = awsSyncService.sync(connector(), JobProgress.NOOP);

        // EC2 + ECR both produced a real asset; Lambda's 403 is reflected in the message but does not
        // take the whole sync down.
        assertThat(result.itemsProcessed()).isEqualTo(2);
        assertThat(result.message()).contains("Lambda functions: 0/0 synced (1 forbidden, 0 errored)");
        assertThat(assetRepository.findByTypeAndName(AssetType.HOST, "i-1")).isPresent();
        assertThat(assetRepository.findByTypeAndName(AssetType.CONTAINER_IMAGE, "app:v1")).isPresent();
    }

    /* ------------------------------------------------------------------ */
    /* Inspector has nothing to say anywhere: clean, not a failure         */
    /* ------------------------------------------------------------------ */

    @Test
    @Transactional
    void zeroInspectorFindingsEverywhereIsACleanCompletion() {
        wireClients();

        stubEc2Instances(Instance.builder().instanceId("i-2").build());
        stubEcrRepositories(Repository.builder().repositoryName("app2").build());
        stubEcrImages("app2", ImageDetail.builder().repositoryName("app2")
                .imageDigest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
                .build());
        stubLambdaFunctions(FunctionConfiguration.builder().functionName("fn-2")
                .functionArn("arn:aws:lambda:us-east-1:123456789012:function:fn-2")
                .build());
        // No stubbing of listFindings beyond the default empty-list answer below.
        when(inspector.listFindings(any(ListFindingsRequest.class)))
                .thenReturn(ListFindingsResponse.builder().findings(List.of()).build());

        IngestResult result = awsSyncService.sync(connector(), JobProgress.NOOP);

        assertThat(result.itemsProcessed()).isEqualTo(3);
        assertThat(result.message()).contains("Amazon Inspector may not be enabled");
        // Inventory value alone still creates the asset, even with zero findings.
        assertThat(assetRepository.findByTypeAndName(AssetType.HOST, "i-2")).isPresent();
        // Untagged image: name falls back to "repository@<short digest>" -- match on the prefix
        // rather than hardcoding the truncated hex, which is an implementation detail of shortDigest.
        assertThat(assetRepository.findAll().stream()
                .anyMatch(a -> a.getType() == AssetType.CONTAINER_IMAGE && a.getName().startsWith("app2@")))
                .isTrue();
        assertThat(assetRepository.findByTypeAndName(AssetType.SERVICE, "fn-2")).isPresent();
    }

    /* ------------------------------------------------------------------ */
    /* Every resource type fails: a real connector failure                */
    /* ------------------------------------------------------------------ */

    @Test
    @Transactional
    void everyResourceTypeFailingMarksTheConnectorFailed() {
        wireClients();

        when(ec2.describeInstances(any(DescribeInstancesRequest.class)))
                .thenThrow(Ec2Exception.builder().message("Access Denied").statusCode(403).build());
        when(ecr.describeRepositories(any(DescribeRepositoriesRequest.class)))
                .thenThrow(EcrException.builder().message("Access Denied").statusCode(403).build());
        when(lambda.listFunctions(any(ListFunctionsRequest.class)))
                .thenThrow(LambdaException.builder().message("Access Denied").statusCode(403).build());

        assertThatThrownBy(() -> awsSyncService.sync(connector(), JobProgress.NOOP))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Every AWS resource type failed to sync");
    }

    /* ------------------------------------------------------------------ */
    /* Stubbing helpers                                                    */
    /* ------------------------------------------------------------------ */

    private void stubEc2Instances(Instance... instances) {
        when(ec2.describeInstances(any(DescribeInstancesRequest.class))).thenReturn(
                DescribeInstancesResponse.builder()
                        .reservations(Reservation.builder().instances(instances).build())
                        .build());
    }

    private void stubEcrRepositories(Repository... repositories) {
        when(ecr.describeRepositories(any(DescribeRepositoriesRequest.class))).thenReturn(
                DescribeRepositoriesResponse.builder().repositories(repositories).build());
    }

    private void stubEcrImages(String repositoryName, ImageDetail... images) {
        when(ecr.describeImages(any(DescribeImagesRequest.class))).thenAnswer(invocation -> {
            DescribeImagesRequest request = invocation.getArgument(0);
            if (!repositoryName.equals(request.repositoryName())) {
                return DescribeImagesResponse.builder().imageDetails(List.of()).build();
            }
            return DescribeImagesResponse.builder().imageDetails(images).build();
        });
    }

    private void seedCve(String cveId) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setId(cveId);
        vulnerabilityRepository.save(vulnerability);
    }

    private void stubLambdaFunctions(FunctionConfiguration... functions) {
        when(lambda.listFunctions(any(ListFunctionsRequest.class))).thenReturn(
                ListFunctionsResponse.builder().functions(functions).build());
    }

    /** Routes {@code listFindings} by the single {@code resourceId} value each call filters on. */
    private void stubFindings(Map<String, ListFindingsResponse> byResourceId) {
        when(inspector.listFindings(any(ListFindingsRequest.class))).thenAnswer(invocation -> {
            ListFindingsRequest request = invocation.getArgument(0);
            String resourceId = request.filterCriteria().resourceId().get(0).value();
            ListFindingsResponse response = byResourceId.get(resourceId);
            return response != null ? response : ListFindingsResponse.builder().findings(List.of()).build();
        });
    }

    private static ListFindingsResponse findingsOf(Finding... findings) {
        return ListFindingsResponse.builder().findings(findings).build();
    }

    private static Finding finding(String cveId, FixAvailable fixAvailable, VulnerablePackage... packages) {
        return Finding.builder()
                .findingArn("arn:aws:inspector2:us-east-1:123456789012:finding/" + cveId)
                .fixAvailable(fixAvailable)
                .packageVulnerabilityDetails(PackageVulnerabilityDetails.builder()
                        .vulnerabilityId(cveId)
                        .vulnerablePackages(packages)
                        .build())
                .build();
    }

    private static VulnerablePackage vulnPackage(String name, String version, PackageManager manager, String fixedInVersion) {
        return VulnerablePackage.builder()
                .name(name)
                .version(version)
                .packageManager(manager)
                .fixedInVersion(fixedInVersion)
                .build();
    }

    /* ------------------------------------------------------------------ */
    /* Assertions helpers                                                  */
    /* ------------------------------------------------------------------ */

    private Asset mustFindAsset(AssetType type, String name) {
        Optional<Asset> asset = assetRepository.findByTypeAndName(type, name);
        assertThat(asset).as("expected an asset (%s, %s)", type, name).isPresent();
        return asset.get();
    }

    private VulnerabilityAlert mustFindAlert(java.util.UUID assetId, String cveId) {
        return alertRepository.findAllByAssetId(assetId).stream()
                .filter(alert -> cveId.equals(alert.getVulnerability().getId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("expected an alert for " + cveId + " on asset " + assetId));
    }

}
