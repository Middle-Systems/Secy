package net.jdesive.secy.service.azure;

import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.persistence.entity.SourceConnectorType;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withUnauthorizedRequest;

/**
 * {@code AzureSyncService} with every Azure call stubbed at the transport (the
 * {@code OsvIngestServiceTest}/{@code ConnectorSyncJobFlowTest} pattern) — {@code secy.azure.*}
 * comes from {@code src/test/resources/application.properties}'s placeholder values, so only the
 * tenant id feeds into the token URL below.
 *
 * <p>Called directly against {@code AzureSyncService.sync(...)} rather than through
 * {@code ConnectorSyncService}/a real job: nothing under test here persists anything onto the
 * {@code SourceConnector} row itself (that lifecycle is {@code SourceConnectorService}'s job, already
 * covered for GitHub by {@code ConnectorSyncJobFlowTest}), so a plain in-memory connector with just
 * {@code type}/{@code scope} set is enough.
 *
 * <p>Every test is {@code @Transactional} — {@code AssetService#applyScan} (the shared ingestion
 * path every connector funnels through) auto-creates and links a real {@code Product} to each
 * {@code Asset}, and without rollback this class's last test to run leaves that {@code Product}
 * permanently committed, blocking any later test class's {@code productRepository.deleteAll()}. The
 * {@code @BeforeEach} cleanup below stays too, as defense against whatever leaks from elsewhere.
 */
@SpringBootTest
class AzureSyncServiceTest {

    private static final String SUBSCRIPTION_ID = "sub-123";
    private static final String TOKEN_URL = "https://login.microsoftonline.com/test-azure-tenant/oauth2/v2.0/token";
    private static final String VM_URL = "https://management.azure.com/subscriptions/" + SUBSCRIPTION_ID
            + "/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01";
    private static final String ACR_URL = "https://management.azure.com/subscriptions/" + SUBSCRIPTION_ID
            + "/providers/Microsoft.ContainerRegistry/registries?api-version=2023-01-01-preview";
    private static final String ASSESSMENTS_URL = "https://management.azure.com/subscriptions/" + SUBSCRIPTION_ID
            + "/providers/Microsoft.Security/assessments?api-version=2020-01-01";

    private static final String VM_ID =
            "/subscriptions/" + SUBSCRIPTION_ID + "/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1";
    private static final String ACR_ID = "/subscriptions/" + SUBSCRIPTION_ID
            + "/resourceGroups/rg1/providers/Microsoft.ContainerRegistry/registries/acr1";
    private static final String ASSESSMENT_VM_ID = VM_ID + "/providers/Microsoft.Security/assessments/assessment-vm1";
    private static final String ASSESSMENT_ACR_ID = ACR_ID + "/providers/Microsoft.Security/assessments/assessment-acr1";

    private static final String VM_SUB_ASSESSMENTS_URL =
            "https://management.azure.com" + ASSESSMENT_VM_ID + "/subAssessments?api-version=2019-01-01-preview";
    private static final String ACR_SUB_ASSESSMENTS_URL =
            "https://management.azure.com" + ASSESSMENT_ACR_ID + "/subAssessments?api-version=2019-01-01-preview";

    @Autowired
    private AzureSyncService azureSyncService;

    @Autowired
    private AssetRepository assetRepository;

    /**
     * Not used to seed anything -- cleared for the same reason {@code ConnectorSyncJobFlowTest}
     * clears it: a {@code compromise_finding} left behind by another test class holds an FK into
     * {@code asset_component} and would block the {@code assetRepository.deleteAll()} below (the H2
     * database is shared across every {@code @SpringBootTest} context in the run).
     */
    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer azure;

    @BeforeEach
    void setUp() {
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        vulnerabilityRepository.deleteAll();
        azure = MockRestServiceServer.bindTo(restTemplate).build();
    }

    /* ------------------------------------------------------------------ */
    /* Happy path: both resource types, mixed Defender fix-availability   */
    /* ------------------------------------------------------------------ */

    @Test
    @Transactional
    void vmsAndRegistriesEnumeratedWithMixedFixAvailabilityDefenderFindings() {
        cve("CVE-2024-1111");
        cve("CVE-2024-2222");
        cve("CVE-2024-3333");
        cve("CVE-2024-4444");

        expectToken();
        azure.expect(requestTo(ASSESSMENTS_URL)).andRespond(withSuccess(assessmentsJson(), MediaType.APPLICATION_JSON));
        azure.expect(requestTo(VM_URL)).andRespond(withSuccess(vmListJson(), MediaType.APPLICATION_JSON));
        azure.expect(requestTo(VM_SUB_ASSESSMENTS_URL))
                .andRespond(withSuccess(vmSubAssessmentsJson(), MediaType.APPLICATION_JSON));
        azure.expect(requestTo(ACR_URL)).andRespond(withSuccess(acrListJson(), MediaType.APPLICATION_JSON));
        azure.expect(requestTo(ACR_SUB_ASSESSMENTS_URL))
                .andRespond(withSuccess(acrSubAssessmentsJson(), MediaType.APPLICATION_JSON));

        IngestResult result = azureSyncService.sync(connector(), JobProgress.NOOP);
        azure.verify();

        assertThat(result.itemsProcessed()).as("one VM asset + one ACR asset").isEqualTo(2);
        assertThat(result.message())
                .contains("1 VM(s)").contains("1 ACR registrie(s)").contains("4 Defender finding(s) mapped");

        Asset vmAsset = assetRepository.findByTypeAndName(AssetType.HOST, "vm1").orElseThrow();
        Asset acrAsset = assetRepository.findByTypeAndName(AssetType.CONTAINER_IMAGE, "acr1.azurecr.io").orElseThrow();

        // The non-CVE sub-assessment on the VM (sub4) never becomes a ScannerFinding -- the funnel
        // is CVE-keyed end to end -- so exactly three alerts land on the VM, not four.
        List<VulnerabilityAlert> vmAlerts = alertRepository.findAllByAssetId(vmAsset.getId());
        assertThat(vmAlerts).hasSize(3);
        assertThat(vmAlerts).extracting(a -> a.getVulnerability().getId())
                .containsExactlyInAnyOrder("CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333");

        VulnerabilityAlert fixed = alertFor(vmAlerts, "CVE-2024-1111");
        assertThat(fixed.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(fixed.getFixedVersions()).isEqualTo("1.2.3");
        assertThat(fixed.getFixSource()).isEqualTo(FixSource.SCANNER);

        VulnerabilityAlert noFix = alertFor(vmAlerts, "CVE-2024-2222");
        assertThat(noFix.getFixState()).isEqualTo(FixState.NO_FIX);
        assertThat(noFix.getFixSource()).isEqualTo(FixSource.SCANNER);

        VulnerabilityAlert unknown = alertFor(vmAlerts, "CVE-2024-3333");
        assertThat(unknown.getFixState()).isEqualTo(FixState.UNKNOWN);

        List<VulnerabilityAlert> acrAlerts = alertRepository.findAllByAssetId(acrAsset.getId());
        assertThat(acrAlerts).hasSize(1);
        assertThat(acrAlerts.get(0).getVulnerability().getId()).isEqualTo("CVE-2024-4444");
    }

    /* ------------------------------------------------------------------ */
    /* Partial failure: one resource type errors, the other still lands   */
    /* ------------------------------------------------------------------ */

    @Test
    @Transactional
    void oneResourceTypeErroringDoesNotFailTheOtherResourceType() {
        expectToken();
        azure.expect(requestTo(ASSESSMENTS_URL)).andRespond(withSuccess(emptyListJson(), MediaType.APPLICATION_JSON));
        azure.expect(requestTo(VM_URL)).andRespond(withServerError());
        azure.expect(requestTo(ACR_URL)).andRespond(withSuccess(acrListJson(), MediaType.APPLICATION_JSON));

        IngestResult result = azureSyncService.sync(connector(), JobProgress.NOOP);
        azure.verify();

        assertThat(result.itemsProcessed()).as("ACR still lands even though VM enumeration failed").isEqualTo(1);
        assertThat(result.message()).contains("VM enumeration failed");

        assertThat(assetRepository.findByTypeAndName(AssetType.HOST, "vm1")).isEmpty();
        assertThat(assetRepository.findByTypeAndName(AssetType.CONTAINER_IMAGE, "acr1.azurecr.io")).isPresent();
    }

    /* ------------------------------------------------------------------ */
    /* Both resource types failing IS real evidence -- total failure      */
    /* ------------------------------------------------------------------ */

    @Test
    @Transactional
    void bothResourceTypesErroringFailsTheSync() {
        expectToken();
        azure.expect(requestTo(ASSESSMENTS_URL)).andRespond(withSuccess(emptyListJson(), MediaType.APPLICATION_JSON));
        azure.expect(requestTo(VM_URL)).andRespond(withServerError());
        azure.expect(requestTo(ACR_URL)).andRespond(withServerError());

        assertThatThrownBy(() -> azureSyncService.sync(connector(), JobProgress.NOOP))
                .isInstanceOf(IllegalStateException.class);
        azure.verify();
    }

    /* ------------------------------------------------------------------ */
    /* Empty subscription + Defender not enabled -- clean completion      */
    /* ------------------------------------------------------------------ */

    @Test
    @Transactional
    void emptySubscriptionAndNoDefenderAssessmentsCompletesCleanly() {
        expectToken();
        azure.expect(requestTo(ASSESSMENTS_URL)).andRespond(withSuccess(emptyListJson(), MediaType.APPLICATION_JSON));
        azure.expect(requestTo(VM_URL)).andRespond(withSuccess(emptyListJson(), MediaType.APPLICATION_JSON));
        azure.expect(requestTo(ACR_URL)).andRespond(withSuccess(emptyListJson(), MediaType.APPLICATION_JSON));

        IngestResult result = azureSyncService.sync(connector(), JobProgress.NOOP);
        azure.verify();

        assertThat(result.itemsProcessed()).isZero();
        assertThat(result.message())
                .as("empty VMs/ACR and no Defender data is a clean, uneventful sync -- not a failure")
                .contains("Microsoft Defender for Cloud may not be enabled");
        assertThat(assetRepository.findAll()).isEmpty();
    }

    /* ------------------------------------------------------------------ */
    /* Token rejection is real evidence of a problem                      */
    /* ------------------------------------------------------------------ */

    @Test
    @Transactional
    void aTokenRejectionFromAzureIsARealFailure() {
        azure.expect(requestTo(TOKEN_URL)).andExpect(method(HttpMethod.POST)).andRespond(withUnauthorizedRequest());

        assertThatThrownBy(() -> azureSyncService.sync(connector(), JobProgress.NOOP))
                .isInstanceOf(IllegalStateException.class);

        // No VM/ACR/assessments call was ever stubbed for this test -- MockRestServiceServer would
        // have failed the test outright had the sync tried to proceed past the rejected token.
        azure.verify();
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private void expectToken() {
        azure.expect(requestTo(TOKEN_URL)).andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess("""
                        {"access_token":"test-token-abc","expires_in":3599,"token_type":"Bearer"}
                        """, MediaType.APPLICATION_JSON));
    }

    private static SourceConnector connector() {
        SourceConnector connector = new SourceConnector();
        connector.setType(SourceConnectorType.AZURE);
        connector.setName("Test Azure connector");
        connector.setScope(SUBSCRIPTION_ID);
        return connector;
    }

    private void cve(String id) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setId(id);
        vulnerability.setDescription("Seeded for an Azure connector test");
        vulnerability.setBaseSeverity("HIGH");
        vulnerability.setCvssScore(7.5d);
        vulnerabilityRepository.save(vulnerability);
    }

    private static VulnerabilityAlert alertFor(List<VulnerabilityAlert> alerts, String cveId) {
        return alerts.stream()
                .filter(a -> cveId.equals(a.getVulnerability().getId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No alert found for " + cveId));
    }

    private static String emptyListJson() {
        return "{\"value\":[]}";
    }

    private static String vmListJson() {
        return """
                {"value":[{"id":"%s","name":"vm1","location":"eastus"}]}
                """.formatted(VM_ID);
    }

    private static String acrListJson() {
        return """
                {"value":[{"id":"%s","name":"acr1","properties":{"loginServer":"acr1.azurecr.io"}}]}
                """.formatted(ACR_ID);
    }

    private static String assessmentsJson() {
        return """
                {"value":[{"id":"%s","name":"assessment-vm1"},{"id":"%s","name":"assessment-acr1"}]}
                """.formatted(ASSESSMENT_VM_ID, ASSESSMENT_ACR_ID);
    }

    /** Three CVE-bearing findings (fixed / no-fix / unknown-fix) plus one non-CVE finding to skip. */
    private static String vmSubAssessmentsJson() {
        return """
                {"value":[
                  {"id":"sub1","name":"sub1","properties":{
                    "vulnerabilityId":"CVE-2024-1111","displayName":"Finding 1",
                    "remediation":"Upgrade to version 1.2.3","additionalData":{"patchable":true}}},
                  {"id":"sub2","name":"sub2","properties":{
                    "vulnerabilityId":"CVE-2024-2222","displayName":"Finding 2",
                    "additionalData":{"patchable":false}}},
                  {"id":"sub3","name":"sub3","properties":{
                    "vulnerabilityId":"CVE-2024-3333","displayName":"Finding 3",
                    "additionalData":{"patchable":true}}},
                  {"id":"sub4","name":"sub4","properties":{
                    "displayName":"Not a CVE finding at all"}}
                ]}
                """;
    }

    private static String acrSubAssessmentsJson() {
        return """
                {"value":[
                  {"id":"sub5","name":"sub5","properties":{
                    "vulnerabilityId":"CVE-2024-4444","displayName":"Finding 4"}}
                ]}
                """;
    }

}
