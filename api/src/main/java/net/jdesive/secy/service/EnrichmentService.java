package net.jdesive.secy.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.config.ActionableProperties;
import net.jdesive.secy.correlation.ComponentCoordinate;
import net.jdesive.secy.correlation.FixResolution;
import net.jdesive.secy.correlation.OsvMatcher;
import net.jdesive.secy.model.component.CorrelatableComponent;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The actionable funnel, in one place.
 *
 * <p><b>An item is actionable when its CVE is on the CISA KEV catalog, or its EPSS probability is
 * strictly above {@code secy.actionable.epss-threshold} — and the CVE record has not been rejected
 * or disputed.</b> That single sentence is the product; every other field this class writes is a
 * denormalized snapshot that exists so {@code GET /actionable} can sort and filter without joining
 * the feed tables per request.
 *
 * <p>The status clause is a veto, not a limb. A {@code REJECTED} CVE describes nothing to fix and a
 * {@code DISPUTED} one describes a judgement call; neither belongs on a list whose promise is "these
 * are the things you must do". Such alerts are still generated, still stored and still reachable
 * through {@code GET /actionable/{id}} and the CVE browser — hidden, not deleted, so an operator who
 * goes looking finds the row and its reason.
 *
 * <p>Called from three places:
 * <ul>
 *   <li>{@code CorrelationService.correlate(SBOM)} — once per matched alert, with the fix data the
 *       match established.</li>
 *   <li>{@code CorrelationService.correlate(Asset, findings)} — the same call, additionally passing
 *       the scanner's own fixed version into {@code scannerFixedVersions}. Asset alerts route through
 *       this class identically to SBOM alerts; there is no second funnel.</li>
 *   <li>{@link #reEnrichAll()} — after a KEV/EPSS/exploit-index ingest succeeds, so alerts raised
 *       before the feed knew about a CVE get promoted, and so {@code fixState} picks up whatever OSV
 *       has learned since. See {@code ReEnrichmentListener}.</li>
 * </ul>
 *
 * <p>Enrichment is deliberately <em>idempotent and total</em>: every call recomputes every field it
 * owns from the CVE's current KEV/EPSS state, so re-running it can demote an alert as well as
 * promote one. The single exception is fix data — see {@link #enrich(VulnerabilityAlert, String)}.
 */
@Slf4j
@Service
public class EnrichmentService {

    /** Alerts re-enriched per flush. Big enough to amortise the round trips, small enough to bound heap. */
    private static final int BATCH_SIZE = 500;

    private final VulnerabilityAlertRepository alertRepository;

    private final ExploitMaturityResolver exploitMaturityResolver;

    private final ActionableProperties properties;

    private final OsvMatcher osvMatcher;

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    public EnrichmentService(VulnerabilityAlertRepository alertRepository,
                             ExploitMaturityResolver exploitMaturityResolver,
                             ActionableProperties properties,
                             OsvMatcher osvMatcher) {
        this.alertRepository = alertRepository;
        this.exploitMaturityResolver = exploitMaturityResolver;
        this.properties = properties;
        this.osvMatcher = osvMatcher;
    }

    /** Enrich an alert with no externally supplied fix information. */
    public void enrich(VulnerabilityAlert alert) {
        enrich(alert, null, null);
    }

    /** Enrich an alert with a fix version an infrastructure scanner reported. */
    public void enrich(VulnerabilityAlert alert, String scannerFixedVersions) {
        enrich(alert, scannerFixedVersions, null);
    }

    /**
     * Recompute every enrichment field on {@code alert} from its CVE.
     *
     * <p>Must run inside a transaction: the KEV and EPSS joins on {@link Vulnerability} are lazy.
     *
     * @param alert                 the alert to populate, with {@code vulnerability} already set
     * @param scannerFixedVersions  fixed version(s) an infrastructure scanner reported for this
     *                              finding, or {@code null}/blank when there are none. When present
     *                              the alert is marked {@link FixState#FIXED} with
     *                              {@link FixSource#SCANNER}.
     * @param correlationFix        what the correlation match said about a fix — {@code OSV} or
     *                              {@code CPE_RANGE} — or {@code null} when correlation had nothing
     *                              to add. When both this and {@code scannerFixedVersions} are
     *                              absent, existing fix data is <em>left alone</em>: re-enrichment
     *                              after a KEV ingest must not erase a fix version that OSV or a
     *                              scanner established earlier.
     */
    public void enrich(VulnerabilityAlert alert, String scannerFixedVersions, FixResolution correlationFix) {
        Vulnerability cve = alert.getVulnerability();

        if (cve == null) {
            // A component match with no CVE behind it cannot clear the funnel. Clear the snapshots
            // too rather than leaving a stale verdict behind — enrichment is total, not additive.
            alert.setActionable(false);
            alert.setActionableReason(null);
            alert.setEpssScore(null);
            alert.setEpssPercentile(null);
            alert.setCvssScore(null);
            alert.setKevDueDate(null);
            alert.setKnownRansomwareUse(null);
            alert.setExploitMaturity(ExploitMaturity.NONE);
            applyFix(alert, scannerFixedVersions, correlationFix);
            return;
        }

        KEV kev = cve.getKev();
        EPSS epss = cve.getEpss();

        Double epssScore = epss == null ? null : widen(epss.getEpss());
        alert.setEpssScore(epssScore);
        alert.setEpssPercentile(epss == null ? null : widen(epss.getPercentile()));
        // NVD leaves the score at 0 for CVEs it has not analysed yet; that is "unknown", not "harmless".
        alert.setCvssScore(cve.getCvssScore() == 0.0d ? null : cve.getCvssScore());

        boolean kevListed = kev != null;
        boolean epssHigh = epssScore != null && epssScore > properties.getEpssThreshold();
        // A rejected or disputed CVE record vetoes both limbs. The snapshots above are still taken,
        // so the row remains sortable and explainable if the CVE List later reinstates the record.
        boolean vetoed = cve.isExcludedFromFunnel();

        alert.setActionable(!vetoed && (kevListed || epssHigh));
        alert.setActionableReason(vetoed ? null : reasonFor(kevListed, epssHigh));

        alert.setKevDueDate(kevListed ? toLocalDate(kev.getDueDate()) : null);
        alert.setKnownRansomwareUse(kevListed ? kev.getKnownRansomwareCampaignUse() : null);

        ExploitMaturity fromKev = kevListed ? ExploitMaturity.IN_THE_WILD : ExploitMaturity.NONE;
        alert.setExploitMaturity(ExploitMaturity.max(fromKev, exploitMaturityResolver.resolve(cve.getId())));

        applyFix(alert, scannerFixedVersions, correlationFix);
    }

    /**
     * Re-run enrichment over every existing alert, in batches.
     *
     * <p>Invoked off the request path (see {@code ReEnrichmentListener}) once a feed ingest has
     * changed what KEV/EPSS know. Pages by {@code id} — a stable key nothing here mutates — and
     * flushes each page so the persistence context does not grow with the alert table.
     *
     * <p>An OSV ingest changes fix data as well as the funnel, so each alert's fix state is
     * re-derived from the mirror on the way past. That lookup is memoised per
     * {@code (ecosystem, package, version)} for the duration of the call: the same dependency
     * usually appears in every SBOM in the estate, and re-querying OSV once per alert would be an
     * N+1 on top of the one this method already has.
     *
     * @return how many alerts were re-evaluated
     */
    @Transactional
    public int reEnrichAll() {
        long total = alertRepository.count();
        if (total == 0) {
            return 0;
        }

        log.info("Re-enriching {} vulnerability alerts against the current KEV/EPSS/OSV state", total);
        int processed = 0;
        int pageNumber = 0;
        Map<String, Optional<FixResolution>> osvCache = new HashMap<>();

        while (true) {
            Page<VulnerabilityAlert> page =
                    alertRepository.findAll(PageRequest.of(pageNumber, BATCH_SIZE, Sort.by("id")));
            List<VulnerabilityAlert> alerts = page.getContent();
            if (alerts.isEmpty()) {
                break;
            }

            alerts.forEach(alert -> enrich(alert, null, osvFixFor(alert, osvCache)));
            alertRepository.saveAll(alerts);
            entityManager.flush();
            entityManager.clear();

            processed += alerts.size();
            if (!page.hasNext()) {
                break;
            }
            pageNumber++;
        }

        log.info("Re-enrichment complete: {} alerts re-evaluated", processed);
        return processed;
    }

    private static ActionableReason reasonFor(boolean kevListed, boolean epssHigh) {
        if (kevListed && epssHigh) {
            return ActionableReason.KEV_AND_EPSS_HIGH;
        }
        if (kevListed) {
            return ActionableReason.KEV;
        }
        if (epssHigh) {
            return ActionableReason.EPSS_HIGH;
        }
        return null;
    }

    /**
     * What OSV currently says about this alert's fix, or empty when it says nothing.
     *
     * <p>Skipped entirely for alerts whose fix came from a source OSV must not overwrite — a
     * scanner-reported version is a statement about the actual installed artefact and outranks a
     * mirror lookup. Memoised across the whole re-enrichment run; see {@link #reEnrichAll()}.
     */
    private FixResolution osvFixFor(VulnerabilityAlert alert, Map<String, Optional<FixResolution>> cache) {
        if (alert.getFixSource() != null && alert.getFixSource() != FixSource.OSV) {
            return null;
        }
        // Whichever component the alert cites — SBOM- or asset-derived. An asset's lodash gets the
        // same OSV re-enrichment a product's does; that is the whole point of the shared interface.
        CorrelatableComponent component = alert.getCorrelatableComponent();
        Vulnerability cve = alert.getVulnerability();
        if (component == null || cve == null || cve.getId() == null) {
            return null;
        }

        ComponentCoordinate coordinate = ComponentCoordinate.of(component);
        if (!coordinate.hasEcosystem() || !coordinate.isVersioned()) {
            return null;
        }

        String key = coordinate.ecosystem() + '|' + coordinate.name() + '|' + coordinate.version()
                + '|' + cve.getId();
        return cache.computeIfAbsent(key, ignored -> osvMatcher.fixFor(coordinate, cve.getId())).orElse(null);
    }

    /**
     * Write the fix columns, honouring the source precedence the roadmap fixed.
     *
     * <p><b>OSV-with-a-version → scanner → any other correlation verdict → leave alone.</b> OSV
     * wins outright when it names a fixed release: it is the upstream project's own statement, per
     * ecosystem, and is the only source that distinguishes "no fix exists" from "we do not know".
     * A scanner's {@code FixedVersion} comes next — it describes the actual installed artefact, and
     * for a distro package it is the only source that knows the distro's backported version. A
     * {@code CPE_RANGE} verdict is an inference from a range boundary and sits below both.
     *
     * <p>When nothing new is offered, existing fix data survives untouched. Re-enrichment runs after
     * every KEV/EPSS ingest and must never erase what an earlier OSV or scanner run established.
     */
    private static void applyFix(VulnerabilityAlert alert, String scannerFixedVersions, FixResolution correlationFix) {
        if (correlationFix != null && correlationFix.source() == FixSource.OSV && correlationFix.isFixed()) {
            apply(alert, correlationFix);
            return;
        }
        if (scannerFixedVersions != null && !scannerFixedVersions.isBlank()) {
            alert.setFixState(FixState.FIXED);
            alert.setFixedVersions(scannerFixedVersions.trim());
            alert.setFixSource(FixSource.SCANNER);
            return;
        }
        if (correlationFix != null && correlationFix.isFixed()) {
            apply(alert, correlationFix);
            return;
        }
        // A NO_FIX / UNKNOWN verdict only overwrites data from the same source (or nothing at all):
        // "OSV has no fix" must not silently erase a scanner-reported version.
        if (correlationFix != null
                && (alert.getFixSource() == null || alert.getFixSource() == correlationFix.source())) {
            apply(alert, correlationFix);
            return;
        }
        if (alert.getFixState() == null) {
            alert.setFixState(FixState.UNKNOWN);
        }
    }

    private static void apply(VulnerabilityAlert alert, FixResolution fix) {
        alert.setFixState(fix.state());
        alert.setFixedVersions(fix.versions());
        alert.setFixSource(fix.source());
    }

    /**
     * Widen an EPSS {@code float} to {@code double} through its decimal representation.
     *
     * <p>A plain cast is wrong here. EPSS publishes five-decimal values and the threshold is
     * configured in decimal, but {@code (double) 0.1f} is {@code 0.10000000149011612} — so a score
     * sitting exactly <em>on</em> the threshold would test as strictly above it and promote an item
     * the operator asked to exclude. Round-tripping through {@link Float#toString} yields the
     * shortest decimal that reproduces the float, which is the number the feed actually published.
     */
    private static double widen(float value) {
        return Double.parseDouble(Float.toString(value));
    }

    /**
     * KEV's {@code dueDate} is a {@code java.util.Date} column. Going through the epoch millis
     * rather than {@code toInstant()} keeps this working when JDBC hands back a
     * {@code java.sql.Date}, whose {@code toInstant()} throws.
     */
    private static LocalDate toLocalDate(Date date) {
        if (date == null) {
            return null;
        }
        return Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault()).toLocalDate();
    }

}
