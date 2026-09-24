package net.jdesive.secy.service.aws;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.asset.ScannedPackage;
import net.jdesive.secy.model.asset.ScannerFinding;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.service.AssetService;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.Reservation;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ecr.EcrClient;
import software.amazon.awssdk.services.ecr.model.DescribeImagesRequest;
import software.amazon.awssdk.services.ecr.model.DescribeImagesResponse;
import software.amazon.awssdk.services.ecr.model.DescribeRepositoriesRequest;
import software.amazon.awssdk.services.ecr.model.DescribeRepositoriesResponse;
import software.amazon.awssdk.services.ecr.model.ImageDetail;
import software.amazon.awssdk.services.ecr.model.Repository;
import software.amazon.awssdk.services.inspector2.Inspector2Client;
import software.amazon.awssdk.services.inspector2.model.Finding;
import software.amazon.awssdk.services.inspector2.model.FilterCriteria;
import software.amazon.awssdk.services.inspector2.model.ListFindingsRequest;
import software.amazon.awssdk.services.inspector2.model.ListFindingsResponse;
import software.amazon.awssdk.services.inspector2.model.PackageVulnerabilityDetails;
import software.amazon.awssdk.services.inspector2.model.StringComparison;
import software.amazon.awssdk.services.inspector2.model.StringFilter;
import software.amazon.awssdk.services.inspector2.model.VulnerablePackage;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.FunctionConfiguration;
import software.amazon.awssdk.services.lambda.model.ListFunctionsRequest;
import software.amazon.awssdk.services.lambda.model.ListFunctionsResponse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The AWS half of Phase 6b's connector sync (ROADMAP.md — "Source & cloud connectors").
 * {@code connector.getScope()} is a single AWS region. Enumerates EC2 instances, ECR repositories'
 * images and Lambda functions into {@link Asset}s via {@link AssetService#findOrCreate}, reads Amazon
 * Inspector v2's own findings for each one, and applies them via {@link AssetService#applyScan} — the
 * exact path Trivy/Grype/Compliance already use. Secy never scans an image itself here.
 *
 * <h2>Client injection, not construction-in-{@code sync()}</h2>
 *
 * <p>The four AWS SDK clients are supplied by an {@link AwsClientFactory} constructor dependency
 * rather than built inline. This is what makes the class unit-testable with no live AWS credentials
 * or network access: a test injects a factory that returns Mockito mocks of {@code Ec2Client}/
 * {@code EcrClient}/{@code LambdaClient}/{@code Inspector2Client}, each stubbed to return canned SDK
 * response objects. See {@link AwsClientFactory}'s Javadoc for why a factory rather than four
 * singleton {@code @Bean} clients (region is per-connector, not knowable at bean-creation time), and
 * {@code AwsConfig} for where the real credentials are read.
 *
 * <h2>Each resource type is its own island — a lesson borrowed from {@code GitHubSyncService}</h2>
 *
 * <p>EC2, ECR and Lambda are enumerated independently, each in its own try/catch, so a permissions
 * failure on one (a Lambda-only deny in the IAM policy, say) never stops the other two from being
 * tried — exactly {@code GitHubSyncService}'s "one bad repo does not fail the sync" philosophy,
 * generalized from repos to resource types. Per-type outcomes are tracked the same way GitHub tracks
 * {@code succeeded}/{@code notFound}/{@code forbidden}/{@code errored}: see {@link TypeResult}.
 *
 * <h2>"Nothing to sync" is not a failure — and neither is "Inspector has nothing to say"</h2>
 *
 * <p>An empty account/region (zero EC2 instances, zero ECR images, zero Lambda functions) is a clean,
 * if uneventful, {@code COMPLETED} — there was nothing to fail at. Amazon Inspector not being enabled
 * for the account/region is treated the same way: {@link #fetchInspectorFindings} swallows whatever
 * {@code Inspector2Client#listFindings} throws and degrades to "zero findings for this resource"
 * rather than failing it, because Secy has no reliable way to distinguish "Inspector was never turned
 * on here" from a transient hiccup, and either way the resource itself was enumerated fine and still
 * has inventory value via {@link AssetService#findOrCreate}. This connector only ever throws — which
 * {@code ConnectorSyncService} turns into {@code SourceConnector.STATUS_FAILED} — when {@link #finish}
 * finds real evidence of a problem: nothing succeeded <em>anywhere</em> across all three resource
 * types, and at least one of them hit a genuine error (an access-denied-shaped exception, invalid
 * credentials, or any other SDK exception enumerating EC2/ECR/Lambda). A permissions failure on one
 * resource type while the others produce real assets is a partial, non-fatal outcome, not a failure —
 * see {@link #finish} and {@code GitHubSyncService}'s class Javadoc for the same reasoning applied to
 * repos instead of resource types.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AwsSyncService {

    private static final String SCANNER_LABEL = "AWS Inspector";

    private final AwsClientFactory clientFactory;
    private final AssetService assetService;

    public IngestResult sync(SourceConnector connector, JobProgress progress) {
        Region region = Region.of(connector.getScope());

        Ec2Client ec2 = clientFactory.ec2Client(region);
        EcrClient ecr = clientFactory.ecrClient(region);
        LambdaClient lambda = clientFactory.lambdaClient(region);
        Inspector2Client inspector = clientFactory.inspector2Client(region);

        AtomicInteger processed = new AtomicInteger();
        try {
            TypeResult ec2Result = syncEc2(connector, ec2, inspector, progress, processed);
            TypeResult ecrResult = syncEcr(connector, ecr, inspector, progress, processed);
            TypeResult lambdaResult = syncLambda(connector, lambda, inspector, progress, processed);

            return finish(connector, ec2Result, ecrResult, lambdaResult);
        } finally {
            closeQuietly(ec2);
            closeQuietly(ecr);
            closeQuietly(lambda);
            closeQuietly(inspector);
        }
    }

    /* ------------------------------------------------------------------ */
    /* EC2                                                                 */
    /* ------------------------------------------------------------------ */

    private TypeResult syncEc2(SourceConnector connector, Ec2Client ec2, Inspector2Client inspector,
                                JobProgress progress, AtomicInteger processed) {
        List<Instance> instances;
        try {
            instances = listInstances(ec2);
        } catch (RuntimeException e) {
            log.warn("EC2 instance enumeration failed for connector {} (region {}): {}",
                    connector.getId(), connector.getScope(), e.toString());
            return TypeResult.enumerationFailure("EC2 instances", isAccessDenied(e));
        }

        int succeeded = 0, forbidden = 0, errored = 0, findings = 0;
        for (Instance instance : instances) {
            checkCancelled(progress, processed);
            try {
                Asset asset = assetService.findOrCreate(AssetType.HOST, ec2AssetName(instance), null,
                        SCANNER_LABEL, null);
                findings += applyInspectorFindings(asset, inspector, instance.instanceId(), progress);
                succeeded++;
            } catch (RuntimeException e) {
                if (isAccessDenied(e)) {
                    forbidden++;
                } else {
                    errored++;
                }
                log.warn("Failed to sync EC2 instance {}: {}", instance.instanceId(), e.toString());
            }
            reportProgress(progress, processed);
        }
        return new TypeResult("EC2 instances", instances.size(), succeeded, forbidden, errored, findings);
    }

    private static List<Instance> listInstances(Ec2Client ec2) {
        List<Instance> instances = new ArrayList<>();
        String nextToken = null;
        do {
            DescribeInstancesRequest.Builder builder = DescribeInstancesRequest.builder();
            if (nextToken != null) {
                builder.nextToken(nextToken);
            }
            DescribeInstancesResponse response = ec2.describeInstances(builder.build());
            for (Reservation reservation : response.reservations()) {
                instances.addAll(reservation.instances());
            }
            nextToken = response.nextToken();
        } while (nextToken != null && !nextToken.isBlank());
        return instances;
    }

    /** The instance's {@code Name} tag when it has one, else its instance id. */
    private static String ec2AssetName(Instance instance) {
        for (Tag tag : instance.tags()) {
            if ("Name".equals(tag.key()) && tag.value() != null && !tag.value().isBlank()) {
                return tag.value();
            }
        }
        return instance.instanceId();
    }

    /* ------------------------------------------------------------------ */
    /* ECR                                                                 */
    /* ------------------------------------------------------------------ */

    private TypeResult syncEcr(SourceConnector connector, EcrClient ecr, Inspector2Client inspector,
                                JobProgress progress, AtomicInteger processed) {
        List<Repository> repositories;
        try {
            repositories = listRepositories(ecr);
        } catch (RuntimeException e) {
            log.warn("ECR repository enumeration failed for connector {} (region {}): {}",
                    connector.getId(), connector.getScope(), e.toString());
            return TypeResult.enumerationFailure("ECR images", isAccessDenied(e));
        }

        int found = 0, succeeded = 0, forbidden = 0, errored = 0, findings = 0;
        for (Repository repository : repositories) {
            List<ImageDetail> images;
            try {
                images = listImages(ecr, repository);
            } catch (RuntimeException e) {
                // One repo's image listing failing does not stop the rest -- same per-resource
                // philosophy as an individual EC2 instance or Lambda function failing below.
                found++;
                if (isAccessDenied(e)) {
                    forbidden++;
                } else {
                    errored++;
                }
                log.warn("Failed to list images for ECR repository {}: {}", repository.repositoryName(), e.toString());
                continue;
            }

            for (ImageDetail image : images) {
                checkCancelled(progress, processed);
                found++;
                try {
                    Asset asset = assetService.findOrCreate(AssetType.CONTAINER_IMAGE,
                            ecrAssetName(repository, image), null, SCANNER_LABEL, null);
                    findings += applyInspectorFindings(asset, inspector, image.imageDigest(), progress);
                    succeeded++;
                } catch (RuntimeException e) {
                    if (isAccessDenied(e)) {
                        forbidden++;
                    } else {
                        errored++;
                    }
                    log.warn("Failed to sync ECR image {}: {}", ecrAssetName(repository, image), e.toString());
                }
                reportProgress(progress, processed);
            }
        }
        return new TypeResult("ECR images", found, succeeded, forbidden, errored, findings);
    }

    private static List<Repository> listRepositories(EcrClient ecr) {
        List<Repository> repositories = new ArrayList<>();
        String nextToken = null;
        do {
            DescribeRepositoriesRequest.Builder builder = DescribeRepositoriesRequest.builder();
            if (nextToken != null) {
                builder.nextToken(nextToken);
            }
            DescribeRepositoriesResponse response = ecr.describeRepositories(builder.build());
            repositories.addAll(response.repositories());
            nextToken = response.nextToken();
        } while (nextToken != null && !nextToken.isBlank());
        return repositories;
    }

    private static List<ImageDetail> listImages(EcrClient ecr, Repository repository) {
        List<ImageDetail> images = new ArrayList<>();
        String nextToken = null;
        do {
            DescribeImagesRequest.Builder builder = DescribeImagesRequest.builder()
                    .repositoryName(repository.repositoryName());
            if (nextToken != null) {
                builder.nextToken(nextToken);
            }
            DescribeImagesResponse response = ecr.describeImages(builder.build());
            images.addAll(response.imageDetails());
            nextToken = response.nextToken();
        } while (nextToken != null && !nextToken.isBlank());
        return images;
    }

    /** {@code repository:tag} for the image's first tag, or {@code repository@<short digest>} when untagged. */
    private static String ecrAssetName(Repository repository, ImageDetail image) {
        if (image.hasImageTags() && !image.imageTags().isEmpty()) {
            return repository.repositoryName() + ":" + image.imageTags().get(0);
        }
        return repository.repositoryName() + "@" + shortDigest(image.imageDigest());
    }

    private static String shortDigest(String digest) {
        if (digest == null || digest.isBlank()) {
            return "untagged";
        }
        int colon = digest.indexOf(':');
        String hex = colon >= 0 ? digest.substring(colon + 1) : digest;
        return hex.length() > 12 ? hex.substring(0, 12) : hex;
    }

    /* ------------------------------------------------------------------ */
    /* Lambda                                                              */
    /* ------------------------------------------------------------------ */

    private TypeResult syncLambda(SourceConnector connector, LambdaClient lambda, Inspector2Client inspector,
                                   JobProgress progress, AtomicInteger processed) {
        List<FunctionConfiguration> functions;
        try {
            functions = listFunctions(lambda);
        } catch (RuntimeException e) {
            log.warn("Lambda function enumeration failed for connector {} (region {}): {}",
                    connector.getId(), connector.getScope(), e.toString());
            return TypeResult.enumerationFailure("Lambda functions", isAccessDenied(e));
        }

        int succeeded = 0, forbidden = 0, errored = 0, findings = 0;
        for (FunctionConfiguration function : functions) {
            checkCancelled(progress, processed);
            try {
                Asset asset = assetService.findOrCreate(AssetType.SERVICE, function.functionName(), null,
                        SCANNER_LABEL, null);
                findings += applyInspectorFindings(asset, inspector, function.functionArn(), progress);
                succeeded++;
            } catch (RuntimeException e) {
                if (isAccessDenied(e)) {
                    forbidden++;
                } else {
                    errored++;
                }
                log.warn("Failed to sync Lambda function {}: {}", function.functionName(), e.toString());
            }
            reportProgress(progress, processed);
        }
        return new TypeResult("Lambda functions", functions.size(), succeeded, forbidden, errored, findings);
    }

    private static List<FunctionConfiguration> listFunctions(LambdaClient lambda) {
        List<FunctionConfiguration> functions = new ArrayList<>();
        String marker = null;
        do {
            ListFunctionsRequest.Builder builder = ListFunctionsRequest.builder();
            if (marker != null) {
                builder.marker(marker);
            }
            ListFunctionsResponse response = lambda.listFunctions(builder.build());
            functions.addAll(response.functions());
            marker = response.nextMarker();
        } while (marker != null && !marker.isBlank());
        return functions;
    }

    /* ------------------------------------------------------------------ */
    /* Inspector findings, shared by all three resource types              */
    /* ------------------------------------------------------------------ */

    /**
     * Fetch Amazon Inspector's findings against one resource and apply them to its asset via
     * {@link AssetService#applyScan}.
     *
     * @return how many Inspector findings were applied (0 is a completely ordinary outcome — see the
     *         class Javadoc)
     */
    private int applyInspectorFindings(Asset asset, Inspector2Client inspector, String resourceId,
                                        JobProgress progress) {
        List<Finding> findings = fetchInspectorFindings(inspector, resourceId);

        Map<String, ScannedPackage> packages = new LinkedHashMap<>();
        List<ScannerFinding> scannerFindings = new ArrayList<>();
        for (Finding finding : findings) {
            String cveId = InspectorFindingMapper.cveIdOf(finding);
            if (cveId == null) {
                continue;
            }
            PackageVulnerabilityDetails details = finding.packageVulnerabilityDetails();
            for (VulnerablePackage vulnerablePackage : details.vulnerablePackages()) {
                ScannedPackage scanned = InspectorFindingMapper.toScannedPackage(vulnerablePackage, asset.getName());
                if (scanned.identityKey() == null) {
                    continue;
                }
                ScannedPackage existing = packages.putIfAbsent(scanned.identityKey(), scanned);
                scannerFindings.add(new ScannerFinding(existing == null ? scanned : existing, cveId,
                        InspectorFindingMapper.fixOf(finding.fixAvailable(), vulnerablePackage.fixedInVersion())));
            }
        }

        assetService.applyScan(asset, List.copyOf(packages.values()), scannerFindings, progress);
        return findings.size();
    }

    /**
     * Amazon Inspector's findings against one resource, filtered by {@code resourceId} (the EC2
     * instance id, the ECR image digest, or the Lambda function ARN — the identifier Inspector itself
     * uses per {@code ResourceType}).
     *
     * <p>Deliberately swallows whatever {@code listFindings} throws rather than propagating it: see
     * the class Javadoc's "nothing to sync is not a failure" section for why an Inspector-specific
     * error (not enabled for this account/region, a scoped-down {@code inspector2:ListFindings} deny,
     * a transient hiccup) degrades this one resource to "zero findings" instead of failing the whole
     * connector. Enumeration failures (EC2/ECR/Lambda describe/list calls) are the real problem
     * signal and are <em>not</em> swallowed — see {@link #syncEc2}/{@link #syncEcr}/{@link #syncLambda}.
     */
    private List<Finding> fetchInspectorFindings(Inspector2Client inspector, String resourceId) {
        try {
            List<Finding> findings = new ArrayList<>();
            String nextToken = null;
            do {
                ListFindingsRequest.Builder builder = ListFindingsRequest.builder()
                        .filterCriteria(FilterCriteria.builder()
                                .resourceId(StringFilter.builder()
                                        .comparison(StringComparison.EQUALS)
                                        .value(resourceId)
                                        .build())
                                .build());
                if (nextToken != null) {
                    builder.nextToken(nextToken);
                }
                ListFindingsResponse response = inspector.listFindings(builder.build());
                findings.addAll(response.findings());
                nextToken = response.nextToken();
            } while (nextToken != null && !nextToken.isBlank());
            return findings;
        } catch (RuntimeException e) {
            log.debug("Inspector findings lookup failed for resource {} (treating as zero findings): {}",
                    resourceId, e.toString());
            return List.of();
        }
    }

    /* ------------------------------------------------------------------ */
    /* Outcome                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * What one resource type's enumeration + per-resource sync did — the AWS analogue of GitHub's
     * {@code succeeded}/{@code notFound}/{@code forbidden}/{@code errored} tally.
     *
     * @param label     human-readable name for the summary message
     * @param found     resources this type enumerated (0 when enumeration itself failed)
     * @param succeeded resources whose asset was created/updated and had its Inspector findings applied
     * @param forbidden resources (or the enumeration call itself) that failed with an
     *                  access-denied-shaped error
     * @param errored   resources (or the enumeration call itself) that failed with any other error
     * @param findings  total Inspector findings applied across this type's resources
     */
    private record TypeResult(String label, int found, int succeeded, int forbidden, int errored, int findings) {

        static TypeResult enumerationFailure(String label, boolean accessDenied) {
            return new TypeResult(label, 0, 0, accessDenied ? 1 : 0, accessDenied ? 0 : 1, 0);
        }

        boolean hadProblem() {
            return forbidden > 0 || errored > 0;
        }
    }

    /**
     * Decide {@code COMPLETED} vs {@code FAILED} and build the summary message.
     *
     * <p>Only throws when nothing succeeded <em>anywhere</em> across all three resource types and at
     * least one of them hit a genuine problem — see the class Javadoc. Zero resources found with no
     * problems (an empty account/region) and zero Inspector findings (Inspector not enabled, or
     * genuinely nothing to report) are both clean, non-fatal outcomes reflected only in the message.
     */
    private IngestResult finish(SourceConnector connector, TypeResult ec2, TypeResult ecr, TypeResult lambda) {
        int totalSucceeded = ec2.succeeded() + ecr.succeeded() + lambda.succeeded();
        int totalFindings = ec2.findings() + ecr.findings() + lambda.findings();
        boolean anyProblem = ec2.hadProblem() || ecr.hadProblem() || lambda.hadProblem();

        String message = String.format(
                "AWS connector sync (%s): %s, %s, %s — %d Inspector findings applied",
                connector.getScope(), typeSummary(ec2), typeSummary(ecr), typeSummary(lambda), totalFindings);
        log.info(message);

        // Mirrors GitHubSyncService: FAILED means "something is broken", not "AWS legitimately has
        // nothing to give us". A permissions failure on one resource type while the others produced
        // real assets is a partial outcome, not a total one.
        if (totalSucceeded == 0 && anyProblem) {
            throw new IllegalStateException("Every AWS resource type failed to sync: " + message);
        }

        String resultMessage = (totalSucceeded > 0 && totalFindings == 0)
                ? message + " — no Inspector findings on any enumerated resource. Amazon Inspector may "
                  + "not be enabled for this account/region; enable it in the Inspector console to get "
                  + "vulnerability findings here."
                : message;
        return new IngestResult(totalSucceeded, resultMessage);
    }

    private static String typeSummary(TypeResult result) {
        return String.format("%s: %d/%d synced (%d forbidden, %d errored)",
                result.label(), result.succeeded(), result.found(), result.forbidden(), result.errored());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private static void checkCancelled(JobProgress progress, AtomicInteger processed) {
        if (progress.isCancelled()) {
            throw new CancellationException("Connector sync cancelled after " + processed.get() + " AWS resources");
        }
    }

    private static void reportProgress(JobProgress progress, AtomicInteger processed) {
        int count = processed.incrementAndGet();
        progress.report(count, "Synced " + count + " AWS resources so far");
    }

    /**
     * True when {@code e} is shaped like an access-denied/authentication failure rather than some
     * other genuine error. Checked by HTTP status and AWS error code rather than by service-specific
     * exception subclass, since the same shape (403, {@code AccessDenied*}) recurs across
     * {@code Ec2Exception}/{@code EcrException}/{@code LambdaException}/{@code Inspector2Exception}.
     */
    private static boolean isAccessDenied(RuntimeException e) {
        if (!(e instanceof AwsServiceException awsException)) {
            return false;
        }
        if (awsException.statusCode() == 403) {
            return true;
        }
        String errorCode = awsException.awsErrorDetails() == null
                ? null
                : awsException.awsErrorDetails().errorCode();
        if (errorCode == null) {
            return false;
        }
        return errorCode.contains("AccessDenied")
                || errorCode.contains("UnrecognizedClient")
                || errorCode.contains("InvalidClientTokenId")
                || errorCode.contains("UnauthorizedOperation")
                || errorCode.contains("AuthFailure");
    }

    private static void closeQuietly(AutoCloseable closeable) {
        try {
            closeable.close();
        } catch (Exception e) {
            log.debug("Failed to close AWS SDK client: {}", e.toString());
        }
    }

}
