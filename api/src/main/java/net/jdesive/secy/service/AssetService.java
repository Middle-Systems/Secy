package net.jdesive.secy.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.CorrelationService;
import net.jdesive.secy.model.asset.AssetDeletionSummary;
import net.jdesive.secy.model.asset.AssetDetailResponse;
import net.jdesive.secy.model.asset.AssetSummaryResponse;
import net.jdesive.secy.model.asset.NormalizedScan;
import net.jdesive.secy.model.asset.ScanFormat;
import net.jdesive.secy.model.asset.ScannedPackage;
import net.jdesive.secy.model.asset.ScannerFinding;
import net.jdesive.secy.model.component.ComponentIdentity;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.AssetComponentRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.asset.AssetScanParser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Persists an infrastructure scan and reconciles the asset's alerts.
 *
 * <h2>Two phases, two transactions — the Phase 3 upload pattern, reused</h2>
 *
 * <ul>
 *   <li>{@link #createPlaceholder} runs synchronously in {@code AssetController}, after
 *       {@code AssetScanParser} has already validated the document (a {@code 400} for a bad shape
 *       happens before this is ever called). It creates or finds the {@code asset} row, stashes the
 *       raw scanner JSON on it and points it at the job that will finish the work, so the {@code 202}
 *       response carries a real asset id immediately.</li>
 *   <li>{@link #ingestScanJob} runs inside the {@code ASSET_SCAN} job. It re-parses the stashed body
 *       (parsing is a pure, cheap function of the bytes), upserts the components, and hands both the
 *       components and the scanner's findings to {@code CorrelationService}.</li>
 * </ul>
 *
 * <h2>Components are upserted, not replaced</h2>
 *
 * <p>The SBOM path writes new component rows per upload, because an SBOM version is a snapshot worth
 * keeping. An asset has no such versioning — there is one current image, re-scanned — so the scan
 * upserts on {@code (asset, identityKey)}. Rows missing from the new scan are flipped to
 * {@code presentInLastScan = false} rather than deleted, which keeps the {@code vulnerability_alert}
 * rows citing them valid and lets those alerts auto-resolve normally.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AssetService {

    /** {@code asset_component.name} / {@code purl}. */
    private static final int MAX_NAME = 512;
    private static final int MAX_VERSION = 255;
    private static final int MAX_PATH = 1024;
    private static final int MAX_ECOSYSTEM = 64;

    /** How many actionable items {@code GET /assets/{id}} embeds by default. */
    public static final int DEFAULT_DETAIL_ITEMS = 25;

    private final AssetRepository assetRepository;
    private final AssetComponentRepository assetComponentRepository;
    private final VulnerabilityAlertRepository alertRepository;
    private final ActionableService actionableService;
    private final CorrelationService correlationService;
    private final AssetScanParser scanParser;
    private final ObjectMapper objectMapper;

    /* ------------------------------------------------------------------ */
    /* Upload                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Create-or-find the asset a scan is for and park the raw document on it.
     *
     * <p>Keyed on {@code (type, name)}: re-scanning {@code acme/api:1.4.2} must land on the row that
     * already holds its components and alerts, or the whole lifecycle has nothing to reconcile
     * against and every scan raises a fresh copy of every alert — the exact bug Phase 3 fixed for
     * SBOMs.
     *
     * @param declaredCpes CPEs the caller declared for the asset; replaces whatever was there when
     *                     non-null, left alone when null, so a scan that does not mention them does
     *                     not silently drop them
     */
    @Transactional
    public Asset createPlaceholder(AssetType type, String name, Product product, ScanFormat format,
                                   Set<String> declaredCpes, String rawBody, UUID jobId) {
        Asset asset = assetRepository.findByTypeAndName(type, name).orElseGet(Asset::new);
        asset.setType(type);
        asset.setName(truncate(name, MAX_NAME));
        if (product != null) {
            asset.setProduct(product);
        }
        if (declaredCpes != null) {
            asset.getDeclaredCpes().clear();
            asset.getDeclaredCpes().addAll(declaredCpes);
        }
        asset.setScanner(format.label());
        asset.setStatus(Asset.STATUS_QUEUED);
        asset.setPendingRawBody(rawBody);
        asset.setPendingScanFormat(format.name());
        asset.setJobId(jobId);
        return assetRepository.saveAndFlush(asset);
    }

    /**
     * The real ingest, run inside the {@code ASSET_SCAN} job.
     *
     * <p>Order matters: components are persisted and flushed <em>before</em> correlation runs, because
     * correlation writes alerts that point at their ids.
     *
     * @throws IllegalStateException if no asset is waiting on this job, or its body is already consumed
     */
    @Transactional
    public IngestResult ingestScanJob(UUID jobId, JobProgress progress) {
        Asset asset = assetRepository.findByJobId(jobId)
                .orElseThrow(() -> new IllegalStateException("No asset is waiting on scan job " + jobId));

        asset.setStatus(Asset.STATUS_PROCESSING);
        assetRepository.saveAndFlush(asset);

        NormalizedScan scan = reparse(asset);
        asset.setPendingRawBody(null);
        asset.setPendingScanFormat(null);

        ScanApplication applied = applyScan(asset, scan.packages(), scan.findings(), progress);
        int present = applied.componentsPresent();
        CorrelationService.CorrelationSummary summary = applied.correlation();

        asset.setLastScannedAt(LocalDateTime.now());
        asset.setStatus(Asset.STATUS_COMPLETED);
        assetRepository.saveAndFlush(asset);

        String message = String.format(
                "%s scan of %s: %d components, %d alerts raised, %d updated, %d auto-resolved%s%s",
                scan.format().label(), asset.getName(), present, summary.created(), summary.updated(),
                summary.autoResolved(),
                summary.skippedUnknownCve() == 0 ? ""
                        : ", " + summary.skippedUnknownCve() + " skipped (CVE not in the NVD mirror yet)",
                scan.skippedFindings() == 0 ? ""
                        : ", " + scan.skippedFindings() + " findings skipped (no CVE id)");
        log.info(message);
        return IngestResult.of(present, message);
    }

    /**
     * Move the asset row for a failed scan job to {@code FAILED}.
     *
     * <p>Runs in its own transaction for the reason {@code SBOMService.markUploadJobFailed} documents:
     * the failure came from {@link #ingestScanJob} throwing, which already rolled back everything it
     * wrote, so only a {@code REQUIRES_NEW} transaction can make this stick.
     *
     * <p>Recoverable by construction: the components and alerts from the last <em>successful</em> scan
     * are untouched, so a failed scan degrades the asset to "stale", never to "empty".
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markScanJobFailed(UUID jobId) {
        assetRepository.findByJobId(jobId).ifPresent(asset -> {
            asset.setStatus(Asset.STATUS_FAILED);
            asset.setPendingRawBody(null);
            asset.setPendingScanFormat(null);
            assetRepository.save(asset);
        });
    }

    /* ------------------------------------------------------------------ */
    /* Component upsert                                                   */
    /* ------------------------------------------------------------------ */

    /** What one {@link #applyScan} pass did. */
    public record ScanApplication(int componentsPresent, CorrelationService.CorrelationSummary correlation) {
    }

    /**
     * Persist a set of observed packages onto an asset and reconcile its alerts.
     *
     * <p>Extracted in Phase 5 so the <b>compliance path shares it verbatim</b>. A CIS report's
     * vulnerability section is the same kind of observation an {@code ASSET_SCAN} makes — "this
     * package, this version, this CVE, on this asset" — so it must produce the same rows, take the
     * same OSV/CPE correlation, get the same enrichment and land in the same {@code GET /actionable}.
     * Giving compliance its own copy of this is precisely how {@code DockerVulnerabilityAlert} ended
     * up outside the funnel for four phases.
     *
     * <p>Order matters: components are persisted and flushed <em>before</em> correlation runs,
     * because correlation writes alerts that point at their ids.
     *
     * @param packages what the scan observed; the asset's declared CPEs are added here, not by callers
     * @param findings the scanner's own {@code (package, CVE)} statements, already resolved to CVE ids
     */
    @Transactional
    public ScanApplication applyScan(Asset asset, List<ScannedPackage> packages,
                                     List<ScannerFinding> findings, JobProgress progress) {
        List<ScannedPackage> observed = new ArrayList<>(packages);
        observed.addAll(declaredCpePackages(asset));

        int present = upsertComponents(asset, observed);
        assetRepository.saveAndFlush(asset);

        if (progress != null) {
            progress.report(present, "Persisted " + present + " components; correlating");
        }

        // Scanner findings become alerts immediately AND count as reproduced for the lifecycle;
        // Secy's own OSV/CPE correlation runs over the same components in the same pass. See
        // CorrelationService.correlate(Asset, List).
        return new ScanApplication(present, correlationService.correlate(asset, findings));
    }

    /**
     * Create-or-find the asset a non-{@code ASSET_SCAN} observation is about.
     *
     * <p>Same {@code (type, name)} key {@link #createPlaceholder} uses, and for the same reason: an
     * observation of {@code acme/api:1.4.2} must land on the row that already holds its components
     * and alerts. Unlike {@code createPlaceholder} it parks no scan body — the compliance path keeps
     * its raw document on its own report row, which is what it is an audit of.
     */
    @Transactional
    public Asset findOrCreate(AssetType type, String name, Product product, String scanner, UUID jobId) {
        Asset asset = assetRepository.findByTypeAndName(type, name).orElseGet(Asset::new);
        asset.setType(type);
        asset.setName(truncate(name, MAX_NAME));
        if (product != null) {
            asset.setProduct(product);
        }
        asset.setScanner(scanner);
        asset.setStatus(Asset.STATUS_QUEUED);
        asset.setJobId(jobId);
        return assetRepository.saveAndFlush(asset);
    }

    /**
     * Reconcile the asset's component rows with what the scan reported.
     *
     * @return how many components the scan reported (i.e. are now present)
     */
    private int upsertComponents(Asset asset, Collection<ScannedPackage> packages) {
        Map<String, AssetComponent> byIdentity = new LinkedHashMap<>();
        for (AssetComponent existing : asset.getComponents()) {
            if (existing.getIdentityKey() != null) {
                byIdentity.putIfAbsent(existing.getIdentityKey(), existing);
            }
        }

        LocalDateTime now = LocalDateTime.now();
        Set<String> seen = new LinkedHashSet<>();

        for (ScannedPackage scanned : packages) {
            String identity = scanned.identityKey();
            if (identity == null) {
                continue;
            }
            AssetComponent component = byIdentity.get(identity);
            if (component == null) {
                component = new AssetComponent();
                component.setAsset(asset);
                asset.getComponents().add(component);
                byIdentity.put(identity, component);
            }
            apply(component, scanned, now);
            seen.add(identity);
        }

        // Everything the scan did not mention is kept but marked absent — see the class note. Its
        // alerts stop being correlated on the next pass and auto-resolve.
        for (Map.Entry<String, AssetComponent> entry : byIdentity.entrySet()) {
            if (!seen.contains(entry.getKey())) {
                entry.getValue().setPresentInLastScan(false);
            }
        }

        assetComponentRepository.saveAll(asset.getComponents());
        assetComponentRepository.flush();
        return seen.size();
    }

    private static void apply(AssetComponent component, ScannedPackage scanned, LocalDateTime now) {
        NormalizedComponent normalized = scanned.component();
        component.setName(truncate(normalized.name(), MAX_NAME));
        component.setVersion(truncate(normalized.version(), MAX_VERSION));
        component.setPurl(truncate(normalized.purl(), MAX_NAME));
        component.setEcosystem(truncate(normalized.ecosystem(), MAX_ECOSYSTEM));
        component.setSource(scanned.source());
        component.setScanTarget(truncate(scanned.scanTarget(), MAX_NAME));
        component.setPackagePath(truncate(scanned.packagePath(), MAX_PATH));
        component.setLayer(truncate(scanned.layer(), MAX_VERSION));
        component.setPresentInLastScan(true);
        component.setLastSeenAt(now);
    }

    /**
     * The operator-declared CPEs, as components.
     *
     * <p>An OS, a firmware image or an appliance has no package manager to enumerate, so the only
     * identity available is the CPE somebody wrote down. Turned into ordinary PURL-less components —
     * which is exactly what an OS package already is — they route through the CPE fallback with no
     * special case anywhere downstream.
     *
     * <p>The component's name is the CPE's {@code product} field, because that is the string
     * {@code PurlCpeBridge} looks for; the version is the CPE's {@code version} when it names a
     * concrete one. A CPE that names neither is skipped rather than stored as an uncorrelatable row.
     */
    private static List<ScannedPackage> declaredCpePackages(Asset asset) {
        List<ScannedPackage> packages = new ArrayList<>();
        for (String cpe : asset.getDeclaredCpes()) {
            net.jdesive.secy.correlation.Cpe23.parse(cpe).ifPresent(parsed -> {
                if (parsed.product() == null || parsed.product().isBlank()) {
                    return;
                }
                String version = parsed.hasConcreteVersion() ? parsed.version() : null;
                packages.add(new ScannedPackage(
                        NormalizedComponent.builder()
                                .name(parsed.product())
                                .version(version)
                                .type("declared-cpe")
                                .build(),
                        AssetComponentSource.DECLARED_CPE, cpe, null, null));
            });
        }
        return packages;
    }

    private NormalizedScan reparse(Asset asset) {
        String rawBody = asset.getPendingRawBody();
        if (rawBody == null || rawBody.isBlank()) {
            throw new IllegalStateException(
                    "Asset row has no pending scan body to ingest — it was already processed, or never received one.");
        }
        ScanFormat format = asset.getPendingScanFormat() == null
                ? ScanFormat.TRIVY
                : ScanFormat.valueOf(asset.getPendingScanFormat());
        JsonNode root;
        try {
            root = objectMapper.readTree(rawBody);
        } catch (IOException e) {
            // AssetController already validated this exact document once; this only fires if the
            // stashed text were corrupted at rest, which the original 400 path never sees.
            throw new IllegalStateException("Stashed scan body failed to re-parse as JSON: " + e.getMessage(), e);
        }
        return scanParser.parse(format, root);
    }

    /* ------------------------------------------------------------------ */
    /* Reads                                                              */
    /* ------------------------------------------------------------------ */

    /** {@code GET /assets} — paged, optionally narrowed by type and/or product. */
    @Transactional(readOnly = true)
    public Page<AssetSummaryResponse> list(int page, int size, AssetType type, UUID productId) {
        Page<Asset> assets = assetRepository.search(type, productId, PageRequest.of(page, size));
        List<UUID> ids = assets.getContent().stream().map(Asset::getId).toList();

        // Two grouped queries for the whole page rather than two per row: the counts are the only
        // thing the list view needs beyond the asset itself, and an N+1 here would scale with the
        // page size for no reason.
        Map<UUID, Long> components = ids.isEmpty() ? Map.of() : tally(assetRepository.countComponentsByAsset(ids));
        Map<UUID, Long> actionable = ids.isEmpty() ? Map.of() : tally(alertRepository.countActionableByAsset(ids));

        return assets.map(asset -> AssetSummaryResponse.of(asset,
                components.getOrDefault(asset.getId(), 0L),
                actionable.getOrDefault(asset.getId(), 0L)));
    }

    /**
     * {@code GET /assets/{id}} — the asset plus its actionable items.
     *
     * <p>The items come from {@link ActionableService} through the ordinary {@code assetId} filter, so
     * they are the same rows, in the same order, with the same shape the Actionable Items screen
     * shows. An asset's findings are not a separate kind of thing.
     */
    @Transactional(readOnly = true)
    public Optional<AssetDetailResponse> findDetail(UUID id, int page, int size) {
        return assetRepository.findById(id).map(asset -> AssetDetailResponse.of(
                asset,
                assetComponentRepository.findAllByAssetIdAndPresentInLastScanTrue(id).size(),
                actionableService.findActionableForAsset(page, size, id)));
    }

    /* ------------------------------------------------------------------ */
    /* Delete                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * {@code DELETE /assets/{id}} — remove the asset, its components and its alerts.
     *
     * <h2>Why this deletes rather than auto-resolves</h2>
     *
     * <p>Phase 2's "never silently delete evidence" rule governs <em>correlation</em>: a scan that no
     * longer reproduces a match must auto-resolve it, never remove it, because the operator did not
     * ask for that and the history matters. An explicit {@code DELETE} is the opposite — it is the
     * operator saying "this asset is not part of my estate any more", and nothing about it is silent.
     *
     * <p>Auto-resolving instead was considered and does not work here: an asset alert's only
     * component reference is an {@code asset_component} row owned by the asset, so keeping the alerts
     * means keeping the asset, and "deleted but still listed" is a worse contract than a delete that
     * deletes. The alerts are counted in the response so the operator sees exactly what went with it.
     *
     * @return what was removed, or empty when the id is unknown
     */
    @Transactional
    public Optional<AssetDeletionSummary> delete(UUID id) {
        Optional<Asset> found = assetRepository.findById(id);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        Asset asset = found.get();

        List<VulnerabilityAlert> alerts = alertRepository.findAllByAssetId(id);
        int componentCount = asset.getComponents().size();

        // Alerts first: they hold the FK into asset_component, and orphanRemoval on the asset would
        // otherwise try to delete the rows out from under them.
        alertRepository.deleteAll(alerts);
        alertRepository.flush();
        assetRepository.delete(asset);

        log.info("Deleted asset {} ({}): {} components, {} alerts", id, asset.getName(),
                componentCount, alerts.size());
        return Optional.of(new AssetDeletionSummary(id, asset.getName(), componentCount, alerts.size()));
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    /** {@code (assetId, count)} rows from a grouped query, as a map. */
    private static Map<UUID, Long> tally(List<Object[]> rows) {
        Map<UUID, Long> counts = new HashMap<>();
        for (Object[] row : rows) {
            counts.put((UUID) row[0], ((Number) row[1]).longValue());
        }
        return counts;
    }

    /**
     * Ingest hardening, same rule as the SBOM path: an over-long field is clipped rather than failing
     * the whole scan. {@code identity_key} is derived from the clipped values on persist and
     * {@link ComponentIdentity} truncates on its own, so the two can never disagree.
     */
    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

}
