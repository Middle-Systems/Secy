package net.jdesive.secy.service.azure;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.FixResolution;
import net.jdesive.secy.model.asset.ScannedPackage;
import net.jdesive.secy.model.asset.ScannerFinding;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.service.AssetService;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The Azure half of Phase 6b's connector sync (ROADMAP.md — "Source & cloud connectors").
 * {@code connector.getScope()} is a single Azure subscription id.
 *
 * <p>Enumerates the subscription's VMs and ACR container registries into {@link Asset}s — the same
 * {@code AssetService#findOrCreate}/{@code applyScan} path Trivy/Grype/compliance scans already use
 * — and reads Microsoft Defender for Cloud's own vulnerability assessments for them. Secy never
 * scans an Azure resource itself; Defender is the scanner, standing in for Trivy/Grype the same way
 * Amazon Inspector does on the AWS side.
 *
 * <h2>ACR: registry-level assets, not per-repository/tag</h2>
 *
 * <p>Enumerating every repository and tag inside a registry needs a second, data-plane token
 * (exchanging the ARM token at {@code https://{loginServer}/oauth2/exchange} for one scoped to that
 * registry) — a genuine extra hop with its own failure modes. Per the locked scope for this task,
 * that is a nice-to-have deferred past v1: one {@link Asset} of type {@link AssetType#CONTAINER_IMAGE}
 * is created per <b>registry</b>, named after its {@code loginServer}, rather than one per
 * repository/tag. This still gives Defender's registry-scoped assessments somewhere to land and
 * keeps the registry in inventory; a future pass can add the data-plane exchange to expand this to
 * per-repository assets without changing anything here.
 *
 * <h2>One bad resource does not fail the sync — and "nothing to sync" is not a failure either</h2>
 *
 * <p>This mirrors {@code GitHubSyncService}'s class Javadoc exactly, applied to Azure's shape
 * instead of GitHub's:
 *
 * <ul>
 *   <li>VM enumeration and ACR enumeration run in their own independent {@code try}/{@code catch} —
 *       a subscription where the service principal can read {@code Microsoft.Compute} but not
 *       {@code Microsoft.ContainerRegistry} (or vice versa) still gets a partial, useful sync rather
 *       than an all-or-nothing failure.</li>
 *   <li>Microsoft Defender for Cloud is an <b>opt-in, paid</b> tier — most subscriptions never turn
 *       it on. An empty (or unreachable) assessments feed is therefore a clean "no findings
 *       available" outcome, exactly like GitHub's "dependency graph not enabled" 404: the assets
 *       are still created (inventory has value on its own), just with zero vulnerability findings
 *       attached.</li>
 *   <li>This method only throws — so {@code ConnectorSyncService} can move the connector to
 *       {@code SourceConnector.STATUS_FAILED} — on real evidence something is broken: the token
 *       endpoint itself rejecting the service principal's credentials, or <em>both</em> VM and ACR
 *       enumeration failing (a role-assignment problem affecting the whole subscription, not just
 *       one resource type). An empty subscription (no VMs, no registries) is a clean, uneventful
 *       {@code COMPLETED} with zero assets — not a failure, and not something retrying fixes.</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AzureSyncService {

    /** Loose enough to survive a documented-but-unverified sub-assessment field name. */
    private static final Pattern CVE_PATTERN = Pattern.compile("CVE-\\d{4}-\\d{4,7}", Pattern.CASE_INSENSITIVE);
    private static final Pattern VERSION_PATTERN = Pattern.compile("\\d+(?:\\.\\d+){1,3}");

    private final AzureApiClient azureApiClient;
    private final AssetService assetService;

    public IngestResult sync(SourceConnector connector, JobProgress progress) {
        String subscriptionId = connector.getScope();

        String accessToken;
        try {
            accessToken = azureApiClient.fetchAccessToken();
        } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.Forbidden e) {
            // Real evidence: the service principal's own credentials (or tenant/app registration)
            // were rejected outright. There is nothing to enumerate without a token, so this always
            // fails the connector -- ConnectorSyncService turns this into STATUS_FAILED.
            throw new IllegalStateException(
                    "Azure token request was rejected (bad tenant id / client id / client secret): "
                            + e.getMessage(), e);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to obtain an Azure access token: " + e.getMessage(), e);
        }

        if (progress.isCancelled()) {
            throw new CancellationException("Connector sync cancelled before any Azure resources were enumerated");
        }

        // Best-effort, subscription-wide, fetched once: Defender for Cloud not being enabled (very
        // common -- it's an opt-in paid tier) or the service principal lacking the Security Reader
        // role must not fail VM/ACR enumeration, which is independently useful inventory on its own.
        List<JsonNode> assessments;
        boolean defenderReachable;
        try {
            assessments = azureApiClient.listSecurityAssessments(subscriptionId, accessToken);
            defenderReachable = true;
        } catch (RuntimeException e) {
            log.info("Microsoft Defender for Cloud assessments unavailable for subscription {} ({}); "
                    + "continuing with inventory only", subscriptionId, e.toString());
            assessments = List.of();
            defenderReachable = false;
        }

        ResourceTypeResult vmResult = syncVirtualMachines(subscriptionId, accessToken, assessments, progress);
        ResourceTypeResult acrResult = syncContainerRegistries(subscriptionId, accessToken, assessments, progress);

        // Only real evidence of a broken connector fails the sync: both resource types' own listing
        // calls threw (a subscription-wide auth/role problem), with the token itself already having
        // been proven good above. Either type alone succeeding -- even with zero resources found --
        // is a legitimate, if uneventful, sync.
        if (!vmResult.enumerationOk && !acrResult.enumerationOk) {
            throw new IllegalStateException(String.format(
                    "Azure connector sync: both VM and ACR registry enumeration failed for subscription %s "
                            + "-- check the service principal's role assignments (Reader on the subscription, "
                            + "or scoped Reader on Microsoft.Compute/Microsoft.ContainerRegistry).",
                    subscriptionId));
        }

        int assetsCreated = vmResult.assetsCreated + acrResult.assetsCreated;
        int findingsMapped = vmResult.findingsMapped + acrResult.findingsMapped;

        String message = String.format(
                "Azure connector sync: %d VM(s) and %d ACR registrie(s) enumerated into %d asset(s), "
                        + "%d Defender finding(s) mapped%s%s",
                vmResult.itemsSeen, acrResult.itemsSeen, assetsCreated, findingsMapped,
                (vmResult.itemErrors > 0 || acrResult.itemErrors > 0)
                        ? String.format(" (%d VM error(s), %d ACR error(s))", vmResult.itemErrors, acrResult.itemErrors)
                        : "",
                !vmResult.enumerationOk ? " -- VM enumeration failed and was skipped"
                        : !acrResult.enumerationOk ? " -- ACR registry enumeration failed and was skipped" : "");

        if (!defenderReachable || assessments.isEmpty()) {
            message += " -- Microsoft Defender for Cloud may not be enabled for this subscription; "
                    + "enable it to get vulnerability findings here.";
        }

        log.info(message);
        return new IngestResult(assetsCreated, message);
    }

    /* ------------------------------------------------------------------ */
    /* Per resource type                                                  */
    /* ------------------------------------------------------------------ */

    /** What one resource type's enumeration + per-resource ingest did. */
    private record ResourceTypeResult(
            boolean enumerationOk, int itemsSeen, int itemErrors, int assetsCreated, int findingsMapped) {
    }

    private ResourceTypeResult syncVirtualMachines(
            String subscriptionId, String accessToken, List<JsonNode> assessments, JobProgress progress) {
        List<AzureApiClient.AzureResource> vms;
        try {
            vms = azureApiClient.listVirtualMachines(subscriptionId, accessToken);
        } catch (RuntimeException e) {
            log.error("Failed to enumerate Azure virtual machines for subscription {}", subscriptionId, e);
            return new ResourceTypeResult(false, 0, 0, 0, 0);
        }

        int itemErrors = 0;
        int assetsCreated = 0;
        int findingsMapped = 0;
        for (AzureApiClient.AzureResource vm : vms) {
            if (progress.isCancelled()) {
                throw new CancellationException("Connector sync cancelled while enumerating Azure VMs");
            }
            try {
                List<ScannerFinding> findings = findingsFor(vm, assessments, accessToken, vm.name());
                Asset asset = assetService.findOrCreate(AssetType.HOST, vm.name(), null, "Azure Defender", null);
                applyFindings(asset, findings, progress);
                assetsCreated++;
                findingsMapped += findings.size();
            } catch (RuntimeException e) {
                log.error("{}: failed to sync Azure VM; skipping and continuing with the rest", vm.name(), e);
                itemErrors++;
            }
            progress.report(assetsCreated, "Synced Azure VM " + vm.name());
        }
        return new ResourceTypeResult(true, vms.size(), itemErrors, assetsCreated, findingsMapped);
    }

    private ResourceTypeResult syncContainerRegistries(
            String subscriptionId, String accessToken, List<JsonNode> assessments, JobProgress progress) {
        List<AzureApiClient.AzureResource> registries;
        try {
            registries = azureApiClient.listContainerRegistries(subscriptionId, accessToken);
        } catch (RuntimeException e) {
            log.error("Failed to enumerate Azure ACR registries for subscription {}", subscriptionId, e);
            return new ResourceTypeResult(false, 0, 0, 0, 0);
        }

        int itemErrors = 0;
        int assetsCreated = 0;
        int findingsMapped = 0;
        for (AzureApiClient.AzureResource registry : registries) {
            if (progress.isCancelled()) {
                throw new CancellationException("Connector sync cancelled while enumerating Azure ACR registries");
            }
            // Registry-level asset, not per-repository/tag -- see the class Javadoc.
            String assetName = registry.loginServer() != null ? registry.loginServer() : registry.name();
            try {
                List<ScannerFinding> findings = findingsFor(registry, assessments, accessToken, assetName);
                Asset asset = assetService.findOrCreate(
                        AssetType.CONTAINER_IMAGE, assetName, null, "Azure Defender", null);
                applyFindings(asset, findings, progress);
                assetsCreated++;
                findingsMapped += findings.size();
            } catch (RuntimeException e) {
                log.error("{}: failed to sync Azure ACR registry; skipping and continuing with the rest",
                        assetName, e);
                itemErrors++;
            }
            progress.report(assetsCreated, "Synced Azure ACR registry " + assetName);
        }
        return new ResourceTypeResult(true, registries.size(), itemErrors, assetsCreated, findingsMapped);
    }

    private void applyFindings(Asset asset, List<ScannerFinding> findings, JobProgress progress) {
        List<ScannedPackage> packages = findings.stream().map(ScannerFinding::pkg).distinct().toList();
        assetService.applyScan(asset, packages, findings, progress);
    }

    /* ------------------------------------------------------------------ */
    /* Defender assessment -> ScannerFinding mapping                      */
    /* ------------------------------------------------------------------ */

    /**
     * Every Defender finding whose assessment is scoped to {@code resource} — matched by the
     * assessment's own ARM resource id containing this resource's id, since a Defender assessment's
     * {@code id} is always {@code {resourceId}/providers/Microsoft.Security/assessments/{name}} (see
     * the class Javadoc on the ACR simplification for why registry-level matching is good enough
     * here too).
     */
    private List<ScannerFinding> findingsFor(
            AzureApiClient.AzureResource resource, List<JsonNode> assessments, String accessToken, String assetName) {
        if (resource.id() == null || assessments.isEmpty()) {
            return List.of();
        }
        String needle = resource.id().toLowerCase(Locale.ROOT);

        List<ScannerFinding> findings = new ArrayList<>();
        for (JsonNode assessment : assessments) {
            String assessmentId = AzureApiClient.textOrNull(assessment, "id");
            if (assessmentId == null || !assessmentId.toLowerCase(Locale.ROOT).contains(needle)) {
                continue;
            }
            List<JsonNode> subAssessments;
            try {
                subAssessments = azureApiClient.listSubAssessments(assessmentId, accessToken);
            } catch (RuntimeException e) {
                log.debug("Failed to fetch Defender sub-assessments for {}: {}", assessmentId, e.toString());
                continue;
            }
            for (JsonNode sub : subAssessments) {
                ScannerFinding finding = toFinding(sub, assetName);
                if (finding != null) {
                    findings.add(finding);
                }
            }
        }
        return findings;
    }

    /**
     * One Defender sub-assessment, mapped to a {@link ScannerFinding} — or {@code null} when it
     * carries nothing that resolves to a CVE id, per {@code ScannerFinding}'s "the funnel is
     * CVE-keyed end to end" contract.
     */
    private static ScannerFinding toFinding(JsonNode subAssessment, String assetName) {
        JsonNode properties = subAssessment.has("properties") ? subAssessment.get("properties") : subAssessment;

        String cveId = extractCveId(properties);
        if (cveId == null) {
            return null;
        }

        ScannedPackage pkg = toPackage(properties, cveId, assetName);
        FixResolution fix = toFixResolution(properties);
        return new ScannerFinding(pkg, cveId, fix);
    }

    private static String extractCveId(JsonNode properties) {
        String direct = firstMatch(AzureApiClient.textOrNull(properties, "vulnerabilityId"));
        if (direct != null) {
            return direct;
        }
        String displayName = firstMatch(AzureApiClient.textOrNull(properties, "displayName"));
        if (displayName != null) {
            return displayName;
        }
        JsonNode additionalData = properties.get("additionalData");
        if (additionalData != null) {
            JsonNode cveArray = additionalData.get("cve");
            if (cveArray != null && cveArray.isArray()) {
                for (JsonNode cve : cveArray) {
                    String match = firstMatch(AzureApiClient.textOrNull(cve, "title"));
                    if (match == null) {
                        match = firstMatch(AzureApiClient.textOrNull(cve, "id"));
                    }
                    if (match != null) {
                        return match;
                    }
                }
            }
        }
        // Last-resort defensive fallback in case the live shape differs from what is documented --
        // see the class Javadoc on AzureApiClient re: coding defensively against an unverified API.
        return firstMatch(properties.toString());
    }

    private static String firstMatch(String text) {
        if (text == null) {
            return null;
        }
        Matcher matcher = CVE_PATTERN.matcher(text);
        return matcher.find() ? matcher.group().toUpperCase(Locale.ROOT) : null;
    }

    /**
     * The affected OS-level package, as best Defender's {@code additionalData} names it. No
     * {@code purl}/{@code ecosystem} is ever set here -- an OS package has neither, and the CPE
     * correlation path is exactly where these are meant to fall (see {@code ScannedPackage}'s
     * Javadoc and the roadmap contract this class's own Javadoc points at).
     */
    private static ScannedPackage toPackage(JsonNode properties, String cveId, String assetName) {
        String name = null;
        String version = null;
        JsonNode additionalData = properties.get("additionalData");
        if (additionalData != null) {
            JsonNode software = additionalData.has("software") ? additionalData.get("software")
                    : additionalData.get("softwareDetails");
            if (software != null) {
                name = AzureApiClient.textOrNull(software, "name");
                if (name == null) {
                    name = AzureApiClient.textOrNull(software, "product");
                }
                version = AzureApiClient.textOrNull(software, "version");
            }
        }
        if (name == null) {
            name = AzureApiClient.textOrNull(properties, "displayName");
        }
        if (name == null) {
            name = "azure-defender-finding-" + cveId;
        }

        NormalizedComponent component = NormalizedComponent.builder().name(name).version(version).build();
        return new ScannedPackage(component, AssetComponentSource.AZURE_DEFENDER, assetName, null, null);
    }

    /**
     * What Defender said about a fix, from whatever combination of {@code additionalData.patchable}
     * and free-text {@code remediation} the sub-assessment carries:
     *
     * <ul>
     *   <li>{@code patchable: false} -- a positive "no fixed release" claim -> {@link FixResolution#noFix}</li>
     *   <li>a version-shaped token inside {@code remediation} -- a concrete fix version -> {@link FixResolution#fixed}</li>
     *   <li>{@code patchable: true} or non-blank {@code remediation} with no version in it -- a fix
     *       exists but no version could be extracted -> {@link FixResolution#unknown}</li>
     *   <li>none of the above -- the scanner said nothing at all -> {@code null}, distinct from
     *       {@code unknown} per {@code ScannerFinding}'s Javadoc</li>
     * </ul>
     */
    private static FixResolution toFixResolution(JsonNode properties) {
        JsonNode additionalData = properties.get("additionalData");
        Boolean patchable = null;
        if (additionalData != null && additionalData.has("patchable") && !additionalData.get("patchable").isNull()) {
            patchable = additionalData.get("patchable").asBoolean();
        }

        if (Boolean.FALSE.equals(patchable)) {
            return FixResolution.noFix(FixSource.SCANNER);
        }

        String remediation = AzureApiClient.textOrNull(properties, "remediation");
        if (remediation != null && !remediation.isBlank()) {
            Matcher versionMatcher = VERSION_PATTERN.matcher(remediation);
            if (versionMatcher.find()) {
                return FixResolution.fixed(versionMatcher.group(), FixSource.SCANNER);
            }
            return FixResolution.unknown(FixSource.SCANNER);
        }

        if (Boolean.TRUE.equals(patchable)) {
            return FixResolution.unknown(FixSource.SCANNER);
        }

        return null;
    }

}
