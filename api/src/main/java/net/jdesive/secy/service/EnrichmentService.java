package net.jdesive.secy.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.config.ActionableProperties;
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
import java.util.List;

/**
 * The actionable funnel, in one place.
 *
 * <p><b>An item is actionable when its CVE is on the CISA KEV catalog, or its EPSS probability is
 * strictly above {@code secy.actionable.epss-threshold}.</b> That single sentence is the product;
 * every other field this class writes is a denormalized snapshot that exists so
 * {@code GET /actionable} can sort and filter without joining the feed tables per request.
 *
 * <p>Called from two places:
 * <ul>
 *   <li>{@link AlertService#generateAlerts(SBOM)} — once per freshly built alert, before save.</li>
 *   <li>{@link #reEnrichAll()} — after a KEV/EPSS (or, later, exploit-index) ingest succeeds, so
 *       alerts raised before the feed knew about a CVE get promoted. See
 *       {@code ReEnrichmentListener}.</li>
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

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    public EnrichmentService(VulnerabilityAlertRepository alertRepository,
                             ExploitMaturityResolver exploitMaturityResolver,
                             ActionableProperties properties) {
        this.alertRepository = alertRepository;
        this.exploitMaturityResolver = exploitMaturityResolver;
        this.properties = properties;
    }

    /** Enrich an alert with no scanner-supplied fix information. */
    public void enrich(VulnerabilityAlert alert) {
        enrich(alert, null);
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
     *                              {@link FixSource#SCANNER}. When absent, existing fix data is
     *                              <em>left alone</em> — re-enrichment after a KEV ingest must not
     *                              erase a fix version that OSV or a scanner established earlier.
     */
    public void enrich(VulnerabilityAlert alert, String scannerFixedVersions) {
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
            applyFix(alert, scannerFixedVersions);
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

        alert.setActionable(kevListed || epssHigh);
        alert.setActionableReason(reasonFor(kevListed, epssHigh));

        alert.setKevDueDate(kevListed ? toLocalDate(kev.getDueDate()) : null);
        alert.setKnownRansomwareUse(kevListed ? kev.getKnownRansomwareCampaignUse() : null);

        ExploitMaturity fromKev = kevListed ? ExploitMaturity.IN_THE_WILD : ExploitMaturity.NONE;
        alert.setExploitMaturity(ExploitMaturity.max(fromKev, exploitMaturityResolver.resolve(cve.getId())));

        applyFix(alert, scannerFixedVersions);
    }

    /**
     * Re-run enrichment over every existing alert, in batches.
     *
     * <p>Invoked off the request path (see {@code ReEnrichmentListener}) once a feed ingest has
     * changed what KEV/EPSS know. Pages by {@code id} — a stable key nothing here mutates — and
     * flushes each page so the persistence context does not grow with the alert table.
     *
     * @return how many alerts were re-evaluated
     */
    @Transactional
    public int reEnrichAll() {
        long total = alertRepository.count();
        if (total == 0) {
            return 0;
        }

        log.info("Re-enriching {} vulnerability alerts against the current KEV/EPSS state", total);
        int processed = 0;
        int pageNumber = 0;

        while (true) {
            Page<VulnerabilityAlert> page =
                    alertRepository.findAll(PageRequest.of(pageNumber, BATCH_SIZE, Sort.by("id")));
            List<VulnerabilityAlert> alerts = page.getContent();
            if (alerts.isEmpty()) {
                break;
            }

            alerts.forEach(this::enrich);
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

    private static void applyFix(VulnerabilityAlert alert, String scannerFixedVersions) {
        if (scannerFixedVersions != null && !scannerFixedVersions.isBlank()) {
            alert.setFixState(FixState.FIXED);
            alert.setFixedVersions(scannerFixedVersions.trim());
            alert.setFixSource(FixSource.SCANNER);
            return;
        }
        if (alert.getFixState() == null) {
            alert.setFixState(FixState.UNKNOWN);
        }
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
