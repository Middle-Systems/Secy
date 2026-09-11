package net.jdesive.secy.correlation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.component.ComponentIdentity;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.EnrichmentService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Turns an SBOM into alerts. This is the correctness gate of the product.
 *
 * <h2>The two paths</h2>
 *
 * <p><b>OSV first.</b> A component with a PURL gives an ecosystem, a package name and a version —
 * exactly OSV's index. If OSV holds any advisory for that package, OSV decides, and the CPE corpus
 * is not consulted at all. A package OSV covers but does not flag at this version is <em>clean</em>,
 * and second-guessing that with CPE name matching is how the old engine produced its false
 * positives.
 *
 * <p><b>CPE second.</b> Components OSV has never heard of, components with no usable PURL, and
 * (from Phase 4) OS and firmware assets fall through to NVD CPE matching via
 * {@link PurlCpeBridge}'s vendor/product guesses. Every alert from this path carries
 * {@code RANGE} or {@code HEURISTIC} confidence, never {@code EXACT}.
 *
 * <h2>Re-scan semantics</h2>
 *
 * <p>{@link #correlate(SBOM)} is idempotent and total for the <b>product</b> the SBOM belongs to:
 *
 * <ul>
 *   <li>a {@code (component identity, CVE)} pair that matches and has no row gets one;</li>
 *   <li>a pair that matches and already has a row updates it in place — <b>never a duplicate</b> —
 *       and is set {@link AlertLifecycleState#ACTIVE}, reviving a previously auto-resolved row;</li>
 *   <li>a row whose match no longer holds becomes {@link AlertLifecycleState#AUTO_RESOLVED}. It is
 *       never deleted: the history matters, and so does whatever triage a human had already done to
 *       it.</li>
 * </ul>
 *
 * <h2>What "the same alert" means, and why Phase 3 had to change it</h2>
 *
 * <p>Phase 2 keyed that reconciliation on {@code (component_id, cveId)}, which only held for
 * <em>re-correlating one SBOM</em>. Every upload writes fresh {@code sbom_component} rows, so a
 * genuinely new SBOM for the same product presented all-new component ids: the existing set came
 * back empty, every alert looked new, and nothing an earlier upload had raised was ever
 * auto-resolved. The lifecycle worked only in the one case nobody hits.
 *
 * <p>The key is now {@code (component identity, cveId)}, where the identity is
 * {@code SBOMComponent.identityKey} — the version-less PURL, stable across uploads — and the
 * candidate set is every alert for the product, not just for this SBOM. So <em>lodash 4.17.20 is
 * vulnerable → ACTIVE; next upload ships 4.17.21 → the same row auto-resolves; a later upload
 * reintroduces 4.17.20 → the same row revives</em>. A carried-forward alert is re-pointed at the
 * component row of the SBOM being correlated, so an alert always cites the evidence that currently
 * supports it.
 *
 * <p><b>Consequence worth knowing:</b> correlating an SBOM makes it the truth for its whole product,
 * so re-correlating a superseded version would auto-resolve the current one's alerts. Nothing does
 * that today — the scan runs once per upload, on the SBOM the upload just made active — and the
 * behaviour is the correct reading of "last scan wins" if anything ever does.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CorrelationService {

    private final OsvMatcher osvMatcher;
    private final CpeMatcher cpeMatcher;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityAlertRepository alertRepository;
    private final EnrichmentService enrichmentService;

    /**
     * What one correlation run did. Returned for logging and tests; nothing persists it.
     *
     * @param componentsScanned   components the SBOM declared
     * @param osvCovered          components OSV holds at least one advisory for
     * @param created             alerts inserted
     * @param updated             existing alerts refreshed (including revived ones)
     * @param autoResolved        existing alerts whose match no longer holds
     * @param skippedUnknownCve   matches dropped because no {@code Vulnerability} row exists yet
     */
    public record CorrelationSummary(int componentsScanned, int osvCovered, int created, int updated,
                                     int autoResolved, int skippedUnknownCve) {
    }

    /**
     * Correlate every component of an SBOM and reconcile the alert table with the result.
     *
     * <p>Must run in a transaction: the component collection and the alert relations are lazy.
     */
    @Transactional
    public CorrelationSummary correlate(SBOM sbom) {
        UUID sbomId = sbom.getId();
        UUID productId = sbom.getProduct() == null ? null : sbom.getProduct().getId();
        log.info("Correlating SBOM {} (product {})", sbomId, productId);

        // Existing alerts, keyed the way a match is keyed. This is what makes the run idempotent.
        // Product-scoped so alerts survive a new SBOM version; an SBOM with no product (only ever a
        // test fixture) falls back to its own scope, which is the Phase 2 behaviour.
        List<VulnerabilityAlert> priorAlerts = productId == null
                ? alertRepository.findAllBySbomIdForCorrelation(sbomId)
                : alertRepository.findAllByProductIdForCorrelation(productId);

        Map<AlertKey, VulnerabilityAlert> existing = new LinkedHashMap<>();
        for (VulnerabilityAlert alert : priorAlerts) {
            // A pre-Phase-3 database can hold two rows for one identity (the duplicate this phase
            // exists to stop creating). Keep the first and let the rest auto-resolve, so the data
            // converges instead of the scan failing — the same reasoning as Phase 2's in-memory
            // uniqueness.
            existing.putIfAbsent(AlertKey.of(alert), alert);
        }

        Map<AlertKey, CorrelationMatch> matches = new LinkedHashMap<>();
        // identity -> the component row of THIS SBOM that carries it, so a carried-forward alert is
        // re-pointed at current evidence rather than at a superseded version's row.
        Map<String, SBOMComponent> componentsByIdentity = new LinkedHashMap<>();
        int osvCovered = 0;
        int componentsScanned = 0;

        for (SBOMComponent component : sbom.getComponents()) {
            if (component == null || component.getId() == null) {
                continue;
            }
            componentsScanned++;
            String identity = identityOf(component);
            componentsByIdentity.put(identity, component);
            ComponentCoordinate coordinate = ComponentCoordinate.of(component);

            OsvMatcher.OsvMatchResult osv = osvMatcher.match(coordinate);
            List<CorrelationMatch> componentMatches;
            if (osv.covered()) {
                osvCovered++;
                componentMatches = osv.matches();
            } else {
                componentMatches = cpeMatcher.match(coordinate);
            }

            for (CorrelationMatch match : componentMatches) {
                AlertKey key = new AlertKey(identity, normalizeCve(match.cveId()));
                matches.merge(key, match, CorrelationMatch::best);
            }
        }

        return reconcile(sbom, existing, matches, componentsByIdentity, componentsScanned, osvCovered);
    }

    /* ------------------------------------------------------------------ */
    /* Reconciliation                                                     */
    /* ------------------------------------------------------------------ */

    private CorrelationSummary reconcile(SBOM sbom,
                                         Map<AlertKey, VulnerabilityAlert> existing,
                                         Map<AlertKey, CorrelationMatch> matches,
                                         Map<String, SBOMComponent> componentsByIdentity,
                                         int componentsScanned,
                                         int osvCovered) {
        LocalDateTime now = LocalDateTime.now();

        // A CVE lookup per distinct id, not per match: several components routinely share one CVE.
        Map<String, Optional<Vulnerability>> cveCache = new HashMap<>();

        List<VulnerabilityAlert> toSave = new ArrayList<>();
        int created = 0;
        int updated = 0;
        int skipped = 0;

        for (Map.Entry<AlertKey, CorrelationMatch> entry : matches.entrySet()) {
            AlertKey key = entry.getKey();
            CorrelationMatch match = entry.getValue();

            Optional<Vulnerability> cve = cveCache.computeIfAbsent(key.cveId(), vulnerabilityRepository::findById);
            if (cve.isEmpty()) {
                // OSV knows a CVE the NVD mirror has not ingested yet. The whole downstream — the
                // funnel, the CVE browser, the detail view — is keyed on a Vulnerability row, so an
                // alert here would be unenrichable and unexplainable. Dropped, counted, and picked
                // up by the next scan once NVD catches up.
                skipped++;
                continue;
            }

            SBOMComponent component = componentsByIdentity.get(key.componentIdentity());
            VulnerabilityAlert alert = existing.get(key);
            if (alert == null) {
                alert = new VulnerabilityAlert();
                alert.setVulnerability(cve.get());
                alert.setCreatedAt(now);
                created++;
            } else {
                updated++;
            }
            // Always (re-)point at the component row of the SBOM just correlated. For a new alert
            // that is the only choice; for a carried-forward one it moves the citation off the
            // superseded SBOM version onto the evidence that currently supports the alert, which is
            // also what keeps GET /sbom/{id}/vulnerabilities describing the active SBOM.
            alert.setComponent(component);

            alert.setMatchConfidence(match.confidence());
            alert.setLifecycleState(AlertLifecycleState.ACTIVE);
            alert.setLastSeenAt(now);
            // The funnel, plus the fix data this match established. Enrichment owns actionable /
            // actionableReason / the EPSS-KEV snapshots; correlation owns only the fix and the
            // confidence.
            enrichmentService.enrich(alert, null, match.fix());

            toSave.add(alert);
        }

        int autoResolved = 0;
        for (Map.Entry<AlertKey, VulnerabilityAlert> entry : existing.entrySet()) {
            if (matches.containsKey(entry.getKey())) {
                continue;
            }
            VulnerabilityAlert stale = entry.getValue();
            if (stale.getLifecycleState() == AlertLifecycleState.AUTO_RESOLVED) {
                continue;
            }
            stale.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            toSave.add(stale);
            autoResolved++;
        }

        if (!toSave.isEmpty()) {
            alertRepository.saveAll(toSave);
        }

        CorrelationSummary summary = new CorrelationSummary(
                componentsScanned, osvCovered, created, updated, autoResolved, skipped);
        log.info("Correlated SBOM {}: {}", sbom.getId(), summary);
        return summary;
    }

    /** CVE ids are uppercase by convention; normalising here keeps the dedup key honest. */
    private static String normalizeCve(String cveId) {
        return cveId == null ? null : cveId.trim().toUpperCase(java.util.Locale.ROOT);
    }

    /**
     * A component's product-stable identity, or a per-row fallback.
     *
     * <p>{@code identityKey} is computed on persist, so it is set for every row correlation ever
     * sees. The recompute here is belt-and-braces for an entity that has been mutated in memory
     * since it was loaded, and the {@code id/} fallback covers the one component that genuinely has
     * no identity — neither a PURL nor a name — for which per-row keying is the honest answer.
     */
    private static String identityOf(SBOMComponent component) {
        String key = ComponentIdentity.keyOf(component.getPurl(), component.getName());
        return key != null ? key : "id/" + component.getId();
    }

    /**
     * The identity of an alert: one row per affected component <em>identity</em> per CVE, where the
     * identity is stable across a product's SBOM versions.
     *
     * <p>This is the uniqueness the re-scan contract promises, enforced in memory rather than by a
     * database constraint so a database carrying duplicates from before this key existed still
     * converges instead of failing the scan.
     */
    private record AlertKey(String componentIdentity, String cveId) {

        static AlertKey of(VulnerabilityAlert alert) {
            return new AlertKey(
                    alert.getComponent() == null ? null : identityOf(alert.getComponent()),
                    alert.getVulnerability() == null ? null : normalizeCve(alert.getVulnerability().getId()));
        }
    }

}
