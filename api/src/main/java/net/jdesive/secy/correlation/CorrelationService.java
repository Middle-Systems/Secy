package net.jdesive.secy.correlation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
 * <p>{@link #correlate(SBOM)} is idempotent and total for the SBOM it is given:
 *
 * <ul>
 *   <li>a {@code (component, CVE)} pair that matches and has no row gets one;</li>
 *   <li>a pair that matches and already has a row updates it in place — <b>never a duplicate</b> —
 *       and is set {@link AlertLifecycleState#ACTIVE}, reviving a previously auto-resolved row;</li>
 *   <li>a row whose match no longer holds becomes {@link AlertLifecycleState#AUTO_RESOLVED}. It is
 *       never deleted: the history matters, and so does whatever triage a human had already done to
 *       it.</li>
 * </ul>
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
        log.info("Correlating SBOM {}", sbomId);

        // Existing alerts, keyed the way a match is keyed. This is what makes the run idempotent.
        Map<AlertKey, VulnerabilityAlert> existing = new LinkedHashMap<>();
        for (VulnerabilityAlert alert : alertRepository.findAllBySbomIdForCorrelation(sbomId)) {
            existing.put(AlertKey.of(alert), alert);
        }

        Map<AlertKey, CorrelationMatch> matches = new LinkedHashMap<>();
        int osvCovered = 0;
        int componentsScanned = 0;

        for (SBOMComponent component : sbom.getComponents()) {
            if (component == null || component.getId() == null) {
                continue;
            }
            componentsScanned++;
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
                AlertKey key = new AlertKey(component.getId(), normalizeCve(match.cveId()));
                matches.merge(key, match, CorrelationMatch::best);
            }
        }

        return reconcile(sbom, existing, matches, componentsScanned, osvCovered);
    }

    /* ------------------------------------------------------------------ */
    /* Reconciliation                                                     */
    /* ------------------------------------------------------------------ */

    private CorrelationSummary reconcile(SBOM sbom,
                                         Map<AlertKey, VulnerabilityAlert> existing,
                                         Map<AlertKey, CorrelationMatch> matches,
                                         int componentsScanned,
                                         int osvCovered) {
        LocalDateTime now = LocalDateTime.now();
        Map<UUID, SBOMComponent> components = new HashMap<>();
        sbom.getComponents().forEach(c -> components.put(c.getId(), c));

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

            VulnerabilityAlert alert = existing.get(key);
            if (alert == null) {
                alert = new VulnerabilityAlert();
                alert.setVulnerability(cve.get());
                alert.setComponent(components.get(key.componentId()));
                alert.setCreatedAt(now);
                created++;
            } else {
                updated++;
            }

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
     * The identity of an alert: one row per affected component per CVE. This is the uniqueness the
     * re-scan contract promises, enforced in memory rather than by a database constraint so a
     * pre-Phase-2 database carrying duplicates still converges instead of failing the scan.
     */
    private record AlertKey(UUID componentId, String cveId) {

        static AlertKey of(VulnerabilityAlert alert) {
            return new AlertKey(
                    alert.getComponent() == null ? null : alert.getComponent().getId(),
                    alert.getVulnerability() == null ? null : normalizeCve(alert.getVulnerability().getId()));
        }
    }

}
