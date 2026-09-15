package net.jdesive.secy.correlation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.asset.ScannerFinding;
import net.jdesive.secy.model.component.ComponentIdentity;
import net.jdesive.secy.model.component.CorrelatableComponent;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.EnrichmentService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiConsumer;

/**
 * Turns an SBOM or a scanned asset into alerts. This is the correctness gate of the product.
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
 * (from Phase 4) OS packages fall through to NVD CPE matching via {@link PurlCpeBridge}'s
 * vendor/product guesses. Every alert from this path carries {@code RANGE} or {@code HEURISTIC}
 * confidence, never {@code EXACT}.
 *
 * <p><b>Plus, for an asset, what the scanner itself said.</b> {@link #correlate(Asset, List)} unions
 * the scanner's own findings into the match set before reconciling. Per the roadmap a
 * scanner-reported CVE becomes an alert immediately, without waiting for OSV or NVD to reproduce it —
 * and just as importantly, a finding Secy's own corpora cannot reproduce is <em>not</em>
 * auto-resolved out from under the operator on the next scan.
 *
 * <h2>Re-scan semantics — idempotent and total, within a scope</h2>
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
 * <h2>What "the same alert" means, and why the scope differs by source</h2>
 *
 * <p>Phase 2 keyed reconciliation on {@code (component_id, cveId)}, which only held for
 * <em>re-correlating one SBOM</em>: every upload writes fresh {@code sbom_component} rows, so a
 * genuinely new SBOM for the same product presented all-new component ids, every alert looked new,
 * and nothing an earlier upload had raised was ever auto-resolved. Phase 3 replaced the key with
 * {@code (identityKey, cveId)} — the version-less PURL, stable across uploads — scoped to the
 * <b>product</b>.
 *
 * <p>Phase 4 keeps that spelling and adds a second scope. An asset's alerts reconcile within the
 * <b>asset</b>, never within its (optional) product:
 *
 * <ul>
 *   <li>An asset need not belong to a product at all, so a product-scoped key has nothing to key on
 *       for most of the estate.</li>
 *   <li>Auto-resolve means "the last scan of <em>this thing</em> no longer reproduces the match". A
 *       product's SBOM and an image scan are two independent observations of two different artefacts.
 *       Sharing a scope would let re-scanning an image that does not ship lodash auto-resolve the
 *       alert the product's SBOM raised against lodash — a silent false negative, and the exact
 *       failure Phase 3 fixed in the opposite direction.</li>
 *   <li>So {@code log4j-core 2.14.1} shipped in a product <em>and</em> baked into one of its images
 *       produces two alerts. That is the true statement: they are two things to patch, in two
 *       places, and fixing the source does not fix the running image. They share an
 *       {@code identityKey}, which is what lets a later phase group them by "the same dependency".</li>
 * </ul>
 *
 * <h2>And, since Phase 6, compromise detection</h2>
 *
 * <p>Both {@code correlate} methods end by handing the same scope to
 * {@link CompromiseDetectionService}, which asks a different question of a different corpus — "is any
 * of this <em>known-bad</em>", rather than "does any of this have a CVE". It writes
 * {@code compromise_finding} rows and touches nothing this class owns. See that class for why it is
 * a sibling rather than a third path inside {@link #matchAll}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CorrelationService {

    /**
     * The confidence a scanner-reported finding claims.
     *
     * <p>Phase 2's note that "only the OSV path can produce {@code EXACT}" described the paths that
     * existed then, and Phase 4 widens it deliberately. {@code matchConfidence} answers <em>"is this
     * really my component?"</em>, not "how was the version range evaluated" — and a scanner read the
     * image's own package database. It is not reporting a declared dependency the way an SBOM does;
     * it is reporting the literal installed build, which is the strongest identification of a
     * component Secy ever gets. The enum's declaration order is untouched.
     */
    private static final MatchConfidence SCANNER_CONFIDENCE = MatchConfidence.EXACT;

    private final OsvMatcher osvMatcher;
    private final CpeMatcher cpeMatcher;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityAlertRepository alertRepository;
    private final EnrichmentService enrichmentService;

    /**
     * Phase 6's third promotion path, run over the same components in the same pass.
     *
     * <p>Called from here rather than from {@code SBOMService}/{@code AssetService} because this is
     * the one place every ingest path already converges on — SBOM upload, Trivy/Grype scan and
     * compliance re-scan all end up in one of the two {@code correlate} methods below, so hooking it
     * here is what makes "runs automatically on ingest, no separate trigger" true for all three
     * without three call sites to keep in step.
     */
    private final CompromiseDetectionService compromiseDetectionService;

    /**
     * What one correlation run did. Returned for logging and tests; nothing persists it.
     *
     * @param componentsScanned   components the SBOM/scan presented
     * @param osvCovered          components OSV holds at least one advisory for
     * @param created             alerts inserted
     * @param updated             existing alerts refreshed (including revived ones)
     * @param autoResolved        existing alerts whose match no longer holds
     * @param skippedUnknownCve   matches dropped because no {@code Vulnerability} row exists yet
     */
    public record CorrelationSummary(int componentsScanned, int osvCovered, int created, int updated,
                                     int autoResolved, int skippedUnknownCve) {
    }

    /* ------------------------------------------------------------------ */
    /* SBOM                                                               */
    /* ------------------------------------------------------------------ */

    /**
     * Correlate every component of an SBOM and reconcile the alert table for its <b>product</b>.
     *
     * <p><b>Consequence worth knowing:</b> correlating an SBOM makes it the truth for its whole
     * product, so re-correlating a superseded version would auto-resolve the current one's alerts.
     * Nothing does that today — the scan runs once per upload, on the SBOM the upload just made
     * active — and the behaviour is the correct reading of "last scan wins" if anything ever does.
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

        // identity -> the component row of THIS SBOM that carries it, so a carried-forward alert is
        // re-pointed at current evidence rather than at a superseded version's row.
        Map<String, SBOMComponent> componentsByIdentity = new LinkedHashMap<>();
        for (SBOMComponent component : sbom.getComponents()) {
            if (component != null && component.getId() != null) {
                componentsByIdentity.put(identityOf(component, component.getId()), component);
            }
        }

        Matches matches = matchAll(componentsByIdentity);

        CorrelationSummary summary = reconcile("SBOM " + sbomId, priorAlerts, matches, Map.of(),
                (alert, identity) -> alert.setComponent(componentsByIdentity.get(identity)));

        compromiseDetectionService.detect(sbom);
        return summary;
    }

    /* ------------------------------------------------------------------ */
    /* Asset                                                              */
    /* ------------------------------------------------------------------ */

    /**
     * Correlate a scanned asset and reconcile the alert table for that <b>asset</b>.
     *
     * <p>Two sources of truth are unioned before reconciliation:
     *
     * <ol>
     *   <li><b>The scanner's findings.</b> Raised as alerts immediately — Secy does not require OSV or
     *       the NVD CPE corpus to agree before reporting what the operator's own scanner found. They
     *       also count as "reproduced" for lifecycle purposes, so a finding only Trivy knows about is
     *       not auto-resolved on the next scan just because Secy's mirrors still do not know it.</li>
     *   <li><b>Secy's own correlation</b> of the same components — OSV first, CPE fallback second,
     *       exactly as for an SBOM. This is what picks up a CVE the scanner's database missed, and
     *       what supplies a fix version when the scanner supplied none.</li>
     * </ol>
     *
     * <p>Only components the last scan still reported are correlated; a row kept as evidence of
     * something since removed from the image is skipped, so its alerts auto-resolve.
     *
     * @param findings the scanner's own statements, already resolved to CVE ids
     */
    @Transactional
    public CorrelationSummary correlate(Asset asset, List<ScannerFinding> findings) {
        UUID assetId = asset.getId();
        log.info("Correlating asset {} ({})", assetId, asset.getName());

        List<VulnerabilityAlert> priorAlerts = alertRepository.findAllByAssetIdForCorrelation(assetId);

        Map<String, AssetComponent> componentsByIdentity = new LinkedHashMap<>();
        for (AssetComponent component : asset.getComponents()) {
            if (component != null && component.getId() != null && component.isPresentInLastScan()) {
                componentsByIdentity.put(identityOf(component, component.getId()), component);
            }
        }

        Matches matches = matchAll(componentsByIdentity);
        Map<AlertKey, FixResolution> scannerFixes = mergeScannerFindings(matches, findings);

        CorrelationSummary summary = reconcile("asset " + assetId, priorAlerts, matches, scannerFixes,
                (alert, identity) -> alert.setAssetComponent(componentsByIdentity.get(identity)));

        compromiseDetectionService.detect(asset);
        return summary;
    }

    /**
     * Fold the scanner's findings into the match set, and pull their fix data aside.
     *
     * <p>The fix travels separately rather than on the {@link CorrelationMatch}, because
     * {@code CorrelationMatch.best} would have to choose between a scanner fix and an OSV fix at
     * merge time and could only keep one. Keeping them apart lets {@code EnrichmentService.applyFix}
     * apply the precedence it already owns, with both values in hand — see
     * {@link #reconcile}.
     *
     * @return the scanner's fix verdict per alert key, for the keys where it had one
     */
    private static Map<AlertKey, FixResolution> mergeScannerFindings(Matches matches,
                                                                     List<ScannerFinding> findings) {
        Map<AlertKey, FixResolution> scannerFixes = new LinkedHashMap<>();
        for (ScannerFinding finding : findings) {
            if (finding == null || finding.cveId() == null || finding.pkg() == null
                    || finding.pkg().identityKey() == null) {
                continue;
            }
            AlertKey key = new AlertKey(finding.pkg().identityKey(), normalizeCve(finding.cveId()));

            CorrelationMatch scannerMatch = new CorrelationMatch(
                    key.cveId(), SCANNER_CONFIDENCE, null, "scanner");
            matches.byKey().merge(key, scannerMatch, CorrelationMatch::best);

            if (finding.fix() != null) {
                scannerFixes.merge(key, finding.fix(), FixResolution::best);
            }
        }
        return scannerFixes;
    }

    /* ------------------------------------------------------------------ */
    /* Matching                                                           */
    /* ------------------------------------------------------------------ */

    /** The match set for one scope, plus the counters the summary reports. */
    private record Matches(Map<AlertKey, CorrelationMatch> byKey, int componentsScanned, int osvCovered) {
    }

    /**
     * Run both correlation paths over a scope's components.
     *
     * <p>Takes {@link CorrelatableComponent}s and so is identical for SBOM and asset components; the
     * engine below {@link ComponentCoordinate} has never known the difference and still does not.
     */
    private Matches matchAll(Map<String, ? extends CorrelatableComponent> componentsByIdentity) {
        Map<AlertKey, CorrelationMatch> matches = new LinkedHashMap<>();
        int osvCovered = 0;

        for (Map.Entry<String, ? extends CorrelatableComponent> entry : componentsByIdentity.entrySet()) {
            String identity = entry.getKey();
            ComponentCoordinate coordinate = ComponentCoordinate.of(entry.getValue());

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

        return new Matches(matches, componentsByIdentity.size(), osvCovered);
    }

    /* ------------------------------------------------------------------ */
    /* Reconciliation                                                     */
    /* ------------------------------------------------------------------ */

    /**
     * The shared upsert-and-auto-resolve pass. Identical for both scopes; all that differs is which
     * FK {@code attach} writes and which alerts were loaded as the prior set.
     *
     * @param attach       points an alert at the component row that currently supports it
     * @param scannerFixes what a scanner said about the fix, per key; empty for the SBOM path
     */
    private CorrelationSummary reconcile(String scopeLabel,
                                         Collection<VulnerabilityAlert> priorAlerts,
                                         Matches matches,
                                         Map<AlertKey, FixResolution> scannerFixes,
                                         BiConsumer<VulnerabilityAlert, String> attach) {
        Map<AlertKey, VulnerabilityAlert> existing = new LinkedHashMap<>();
        for (VulnerabilityAlert alert : priorAlerts) {
            // A pre-Phase-3 database can hold two rows for one identity (the duplicate that key
            // exists to stop creating). Keep the first and let the rest auto-resolve, so the data
            // converges instead of the scan failing — the same reasoning as Phase 2's in-memory
            // uniqueness.
            existing.putIfAbsent(AlertKey.of(alert), alert);
        }

        LocalDateTime now = LocalDateTime.now();

        // A CVE lookup per distinct id, not per match: several components routinely share one CVE.
        Map<String, Optional<Vulnerability>> cveCache = new HashMap<>();

        List<VulnerabilityAlert> toSave = new ArrayList<>();
        int created = 0;
        int updated = 0;
        int skipped = 0;

        for (Map.Entry<AlertKey, CorrelationMatch> entry : matches.byKey().entrySet()) {
            AlertKey key = entry.getKey();
            CorrelationMatch match = entry.getValue();

            Optional<Vulnerability> cve = cveCache.computeIfAbsent(key.cveId(), vulnerabilityRepository::findById);
            if (cve.isEmpty()) {
                // OSV or a scanner knows a CVE the NVD mirror has not ingested yet. The whole
                // downstream — the funnel, the CVE browser, the detail view — is keyed on a
                // Vulnerability row, so an alert here would be unenrichable and unexplainable.
                // Dropped, counted, and picked up by the next scan once NVD catches up.
                skipped++;
                continue;
            }

            VulnerabilityAlert alert = existing.get(key);
            if (alert == null) {
                alert = new VulnerabilityAlert();
                alert.setVulnerability(cve.get());
                alert.setCreatedAt(now);
                created++;
            } else {
                updated++;
            }
            // Always (re-)point at the component row this scope currently carries. For a new alert
            // that is the only choice; for a carried-forward one it moves the citation off a
            // superseded SBOM version, or off a stale scan's row, onto the evidence that supports the
            // alert now.
            attach.accept(alert, key.componentIdentity());

            alert.setMatchConfidence(match.confidence());
            alert.setLifecycleState(AlertLifecycleState.ACTIVE);
            alert.setLastSeenAt(now);

            // The funnel, plus the fix data this match established. Enrichment owns actionable /
            // actionableReason / the EPSS-KEV snapshots and the fix-source precedence; correlation
            // owns only the confidence and what each source had to say.
            FixResolution scannerFix = scannerFixes.get(key);
            enrichmentService.enrich(alert, scannerVersions(scannerFix),
                    correlationFix(match.fix(), scannerFix));

            toSave.add(alert);
        }

        int autoResolved = 0;
        for (Map.Entry<AlertKey, VulnerabilityAlert> entry : existing.entrySet()) {
            if (matches.byKey().containsKey(entry.getKey())) {
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
                matches.componentsScanned(), matches.osvCovered(), created, updated, autoResolved, skipped);
        log.info("Correlated {}: {}", scopeLabel, summary);
        return summary;
    }

    /**
     * The scanner's fixed version(s), routed to {@code EnrichmentService}'s {@code scannerFixedVersions}
     * slot so the precedence in {@code applyFix} does the deciding.
     *
     * <p>That slot sits <b>above</b> a {@code CPE_RANGE} verdict and <b>below</b> OSV naming a fixed
     * release, which is exactly right at scan time: a range boundary inferred from an NVD row must
     * never overwrite the backported build a distro scanner read off the package database, and the
     * upstream project's own per-ecosystem fix statement still wins when it has one. None of the
     * Phase 2 precedence rules changed to make this work.
     */
    private static String scannerVersions(FixResolution scannerFix) {
        return scannerFix != null && scannerFix.isFixed() ? scannerFix.versions() : null;
    }

    /**
     * What correlation contributes to the fix decision.
     *
     * <p>A scanner {@code NO_FIX} is a positive claim ("no fixed release exists") and travels here so
     * it can be recorded when nothing better exists — {@code applyFix} will only let it overwrite
     * data from the same source. A scanner {@code FIXED} does not: that goes through
     * {@link #scannerVersions} instead, so the two never compete for the same slot.
     */
    private static FixResolution correlationFix(FixResolution matchFix, FixResolution scannerFix) {
        if (scannerFix == null || scannerFix.isFixed()) {
            return matchFix;
        }
        if (matchFix != null && matchFix.source() == FixSource.OSV && matchFix.isFixed()) {
            return matchFix;
        }
        return FixResolution.best(matchFix, scannerFix);
    }

    /** CVE ids are uppercase by convention; normalising here keeps the dedup key honest. */
    private static String normalizeCve(String cveId) {
        return cveId == null ? null : cveId.trim().toUpperCase(java.util.Locale.ROOT);
    }

    /**
     * A component's scope-stable identity, or a per-row fallback.
     *
     * <p>{@code identityKey} is computed on persist, so it is set for every row correlation ever
     * sees. The recompute here is belt-and-braces for an entity that has been mutated in memory
     * since it was loaded, and the {@code id/} fallback covers the one component that genuinely has
     * no identity — neither a PURL nor a name — for which per-row keying is the honest answer.
     */
    private static String identityOf(CorrelatableComponent component, UUID rowId) {
        String key = ComponentIdentity.keyOf(component.getPurl(), component.getName());
        return key != null ? key : "id/" + rowId;
    }

    /**
     * The identity of an alert: one row per affected component <em>identity</em> per CVE, within the
     * scope that produced it — a product for SBOM-derived alerts, an asset for scanner-derived ones.
     *
     * <p>This is the uniqueness the re-scan contract promises, enforced in memory rather than by a
     * database constraint so a database carrying duplicates from before this key existed still
     * converges instead of failing the scan.
     */
    private record AlertKey(String componentIdentity, String cveId) {

        static AlertKey of(VulnerabilityAlert alert) {
            CorrelatableComponent component = alert.getCorrelatableComponent();
            UUID rowId = alert.getComponent() != null
                    ? alert.getComponent().getId()
                    : (alert.getAssetComponent() == null ? null : alert.getAssetComponent().getId());
            return new AlertKey(
                    component == null ? null : identityOf(component, rowId),
                    alert.getVulnerability() == null ? null : normalizeCve(alert.getVulnerability().getId()));
        }
    }

}
