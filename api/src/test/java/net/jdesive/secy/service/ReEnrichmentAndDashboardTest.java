package net.jdesive.secy.service;

import net.jdesive.secy.model.DashboardStats;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two things that make the funnel a living thing rather than a one-shot flag: re-enrichment
 * after a feed changes, and the dashboard roll-ups that read the same columns.
 *
 * <p>Deliberately <b>not</b> {@code @Transactional} — {@code reEnrichAll()} manages its own
 * transaction and clears the persistence context between batches, so the assertions have to read
 * back through the repository the way the application would.
 */
@SpringBootTest
class ReEnrichmentAndDashboardTest {

    @Autowired
    private EnrichmentService enrichmentService;

    @Autowired
    private StatisticsService statisticsService;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private KEVRepository kevRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @BeforeEach
    void clear() {
        // The H2 database is shared by every @SpringBootTest context in the run, and reEnrichAll()
        // sweeps the whole alert table — start from an empty one.
        alertRepository.deleteAll();
        cveRepository.deleteAll();
        kevRepository.deleteAll();
        epssRepository.deleteAll();
    }

    /* ------------------------------------------------------------------ */
    /* Re-enrichment                                                      */
    /* ------------------------------------------------------------------ */

    @Test
    void anAlertIsPromotedWhenItsCveLandsOnTheKevCatalog() {
        Vulnerability cve = cve("CVE-2099-3001", "HIGH", 7.5d);
        UUID alertId = alert(cve, a -> { });

        assertThat(alertRepository.findById(alertId).orElseThrow().isActionable())
                .as("nothing known about this CVE yet")
                .isFalse();

        // CISA adds it overnight. Nothing re-scans the SBOM; only the feed changed.
        LocalDate due = LocalDate.now().plusDays(14);
        kev(cve, due, "Known");

        assertThat(enrichmentService.reEnrichAll()).isEqualTo(1);

        VulnerabilityAlert promoted = alertRepository.findById(alertId).orElseThrow();
        assertThat(promoted.isActionable()).isTrue();
        assertThat(promoted.getActionableReason()).isEqualTo(ActionableReason.KEV);
        assertThat(promoted.getExploitMaturity()).isEqualTo(ExploitMaturity.IN_THE_WILD);
        assertThat(promoted.getKevDueDate()).isEqualTo(due);
        assertThat(promoted.getKnownRansomwareUse()).isEqualTo("Known");
    }

    @Test
    void anAlertIsPromotedWhenEpssCrossesTheThreshold() {
        Vulnerability cve = cve("CVE-2099-3002", "MEDIUM", 5.0d);
        epss(cve, 0.05f, 0.6f);
        UUID alertId = alert(cve, a -> { });
        enrichmentService.reEnrichAll();
        assertThat(alertRepository.findById(alertId).orElseThrow().isActionable()).isFalse();

        // The next EPSS pull re-scores it.
        epss(cve, 0.42f, 0.95f);
        enrichmentService.reEnrichAll();

        VulnerabilityAlert promoted = alertRepository.findById(alertId).orElseThrow();
        assertThat(promoted.isActionable()).isTrue();
        assertThat(promoted.getActionableReason()).isEqualTo(ActionableReason.EPSS_HIGH);
        assertThat(promoted.getEpssScore()).isEqualTo(0.42d);
        assertThat(promoted.getEpssPercentile()).isEqualTo(0.95d);
    }

    @Test
    void reEnrichmentDemotesAnAlertWhoseSignalWentAway() {
        Vulnerability cve = cve("CVE-2099-3003", "HIGH", 7.0d);
        UUID alertId = alert(cve, a -> {
            // A stale verdict from an earlier EPSS score that no longer exists.
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.8d);
        });

        enrichmentService.reEnrichAll();

        VulnerabilityAlert demoted = alertRepository.findById(alertId).orElseThrow();
        assertThat(demoted.isActionable()).isFalse();
        assertThat(demoted.getActionableReason()).isNull();
        assertThat(demoted.getEpssScore()).isNull();
    }

    @Test
    void reEnrichingAnEmptyEstateIsANoOp() {
        assertThat(enrichmentService.reEnrichAll()).isZero();
    }

    /* ------------------------------------------------------------------ */
    /* Dashboard                                                          */
    /* ------------------------------------------------------------------ */

    @Test
    void theDashboardCountsTheFunnelsOutput() {
        Vulnerability critical = cve("CVE-2099-3101", "CRITICAL", 9.8d);
        Vulnerability high = cve("CVE-2099-3102", "HIGH", 8.1d);
        Vulnerability medium = cve("CVE-2099-3103", "MEDIUM", 5.5d);
        Vulnerability low = cve("CVE-2099-3104", "LOW", 3.1d);
        Vulnerability quiet = cve("CVE-2099-3105", "CRITICAL", 9.0d);

        // KEV only, overdue, no fix known.
        alert(critical, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.KEV);
            a.setExploitMaturity(ExploitMaturity.IN_THE_WILD);
            a.setKevDueDate(LocalDate.now().minusDays(3));
            a.setCreatedAt(LocalDateTime.now().minusDays(1));
        });
        // EPSS only, patch available.
        alert(high, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.9d);
            a.setFixState(FixState.FIXED);
            a.setFixedVersions("3.0.1");
            a.setFixSource(FixSource.SCANNER);
            a.setCreatedAt(LocalDateTime.now().minusDays(2));
        });
        // Both limbs, weaponized, upstream says there will be no fix. Older than the trend window.
        alert(medium, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.KEV_AND_EPSS_HIGH);
            a.setEpssScore(0.7d);
            a.setExploitMaturity(ExploitMaturity.WEAPONIZED);
            a.setFixState(FixState.NO_FIX);
            a.setKevDueDate(LocalDate.now().plusDays(20));
            a.setCreatedAt(LocalDateTime.now().minusDays(30));
        });
        alert(low, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.5d);
            a.setExploitMaturity(ExploitMaturity.POC);
            a.setFixState(FixState.FIXED);
            a.setFixedVersions("1.4.0");
            a.setCreatedAt(LocalDateTime.now().minusDays(3));
        });
        // High CVSS but outside the funnel — must not appear in any actionable tile.
        alert(quiet, a -> a.setCreatedAt(LocalDateTime.now().minusDays(1)));

        DashboardStats stats = statisticsService.getDashboardMetrics();

        assertThat(stats.getOpenActionableCount()).isEqualTo(4);

        // Overlapping on purpose: KEV_AND_EPSS_HIGH is counted in both.
        assertThat(stats.getActionableKevCount()).isEqualTo(2);
        assertThat(stats.getActionableEpssCount()).isEqualTo(3);

        assertThat(stats.getActionableCrit()).isEqualTo(1);
        assertThat(stats.getActionableHigh()).isEqualTo(1);
        assertThat(stats.getActionableMed()).isEqualTo(1);
        assertThat(stats.getActionableLow()).isEqualTo(1);

        assertThat(stats.getActionableWithFixCount()).isEqualTo(2);
        assertThat(stats.getActionableNoFixCount()).isEqualTo(2);

        assertThat(stats.getActionableExploitNone()).isEqualTo(1);
        assertThat(stats.getActionableExploitPoc()).isEqualTo(1);
        assertThat(stats.getActionableExploitWeaponized()).isEqualTo(1);
        assertThat(stats.getActionableExploitInTheWild()).isEqualTo(1);

        assertThat(stats.getPastKevDueCount()).isEqualTo(1);
        assertThat(stats.getActionableCreatedLast7d()).isEqualTo(3);
    }

    /* ------------------------------------------------------------------ */
    /* Seeding helpers                                                    */
    /* ------------------------------------------------------------------ */

    private Vulnerability cve(String id, String severity, double cvss) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded CVE " + id);
        cve.setBaseSeverity(severity);
        cve.setCvssScore(cvss);
        return cveRepository.save(cve);
    }

    private void kev(Vulnerability cve, LocalDate dueDate, String ransomware) {
        KEV kev = new KEV();
        kev.setCveId(cve.getId());
        kev.setName("Seeded KEV entry for " + cve.getId());
        kev.setAdded(LocalDateTime.now().minusDays(1));
        kev.setDueDate(Date.from(dueDate.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        kev.setKnownRansomwareCampaignUse(ransomware);
        kevRepository.save(kev);
    }

    private void epss(Vulnerability cve, float score, float percentile) {
        EPSS epss = new EPSS();
        epss.setCve(cve.getId());
        epss.setEpss(score);
        epss.setPercentile(percentile);
        epss.setDate(LocalDateTime.now());
        epssRepository.save(epss);
    }

    private UUID alert(Vulnerability cve, Consumer<VulnerabilityAlert> enrichment) {
        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        enrichment.accept(alert);
        return alertRepository.save(alert).getId();
    }

}
