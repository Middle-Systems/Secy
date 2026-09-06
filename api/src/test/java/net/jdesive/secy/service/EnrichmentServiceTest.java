package net.jdesive.secy.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.config.ActionableProperties;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The funnel itself: <em>KEV-listed OR EPSS strictly above the threshold</em>, and the denormalized
 * snapshots that come with it.
 *
 * <p>Alerts are built in memory rather than persisted — enrichment reads the CVE and writes the
 * alert, and nothing in between needs a row. The CVEs and their KEV/EPSS rows are real, because the
 * lazy one-to-one joins on {@link Vulnerability} are exactly what enrichment consults.
 */
@SpringBootTest
@Transactional
class EnrichmentServiceTest {

    /** The stub resolver below claims a PoC exists for this one CVE and nothing else. */
    private static final String CVE_WITH_PUBLIC_POC = "CVE-2099-0POC";

    @Autowired
    private EnrichmentService enrichmentService;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private KEVRepository kevRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private ActionableProperties properties;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Stands in for the exploit-index feed that has not been built yet, and proves the
     * {@link ExploitMaturityResolver} seam is actually consulted: a {@code @Primary} bean out-ranks
     * {@link KevOnlyExploitMaturityResolver} without {@code EnrichmentService} changing.
     */
    @TestConfiguration
    static class StubExploitIndex {
        @Bean
        @Primary
        ExploitMaturityResolver stubResolver() {
            return cveId -> CVE_WITH_PUBLIC_POC.equals(cveId) ? ExploitMaturity.POC : ExploitMaturity.NONE;
        }
    }

    /* ------------------------------------------------------------------ */
    /* The funnel                                                         */
    /* ------------------------------------------------------------------ */

    @Test
    void aKevListedCveIsActionableEvenWithNoEpssData() {
        LocalDate due = LocalDate.of(2026, 3, 1);
        Vulnerability cve = seed("CVE-2099-1001", null, due, "Known");

        VulnerabilityAlert alert = enrich(cve);

        assertThat(alert.isActionable()).isTrue();
        assertThat(alert.getActionableReason()).isEqualTo(ActionableReason.KEV);
        assertThat(alert.getExploitMaturity()).isEqualTo(ExploitMaturity.IN_THE_WILD);
        assertThat(alert.getKevDueDate()).isEqualTo(due);
        assertThat(alert.getKnownRansomwareUse()).isEqualTo("Known");
        assertThat(alert.getEpssScore()).isNull();
        assertThat(alert.getEpssPercentile()).isNull();
    }

    @Test
    void aHighEpssCveIsActionableWithoutKev() {
        Vulnerability cve = seed("CVE-2099-1002", 0.5f, null, null);

        VulnerabilityAlert alert = enrich(cve);

        assertThat(alert.isActionable()).isTrue();
        assertThat(alert.getActionableReason()).isEqualTo(ActionableReason.EPSS_HIGH);
        assertThat(alert.getEpssScore()).isEqualTo(0.5d);
        assertThat(alert.getEpssPercentile()).isEqualTo(0.97d);
        // No KEV entry, and no other exploit index has anything on this CVE.
        assertThat(alert.getExploitMaturity()).isEqualTo(ExploitMaturity.NONE);
        assertThat(alert.getKevDueDate()).isNull();
        assertThat(alert.getKnownRansomwareUse()).isNull();
    }

    @Test
    void bothLimbsFiringIsItsOwnReason() {
        Vulnerability cve = seed("CVE-2099-1003", 0.9f, LocalDate.of(2026, 1, 15), "Unknown");

        VulnerabilityAlert alert = enrich(cve);

        assertThat(alert.isActionable()).isTrue();
        assertThat(alert.getActionableReason()).isEqualTo(ActionableReason.KEV_AND_EPSS_HIGH);
        assertThat(alert.getExploitMaturity()).isEqualTo(ExploitMaturity.IN_THE_WILD);
    }

    @Test
    void aCveWithNeitherSignalIsNotActionable() {
        Vulnerability cve = seed("CVE-2099-1004", 0.01f, null, null);

        VulnerabilityAlert alert = enrich(cve);

        assertThat(alert.isActionable()).isFalse();
        assertThat(alert.getActionableReason()).isNull();
        // The snapshots are still taken — the row has to be sortable if it is ever promoted.
        assertThat(alert.getEpssScore()).isEqualTo(0.01d);
    }

    /* ------------------------------------------------------------------ */
    /* The threshold boundary                                             */
    /* ------------------------------------------------------------------ */

    @Test
    void epssExactlyAtTheThresholdIsNotActionable() {
        assertThat(properties.getEpssThreshold()).isEqualTo(0.1d);
        Vulnerability cve = seed("CVE-2099-1005", 0.1f, null, null);

        VulnerabilityAlert alert = enrich(cve);

        // The funnel is "> threshold", not ">=". A float widened by a plain cast would land at
        // 0.10000000149011612 and quietly promote this row.
        assertThat(alert.getEpssScore()).isEqualTo(0.1d);
        assertThat(alert.isActionable()).isFalse();
    }

    @Test
    void epssJustAboveTheThresholdIsActionable() {
        Vulnerability cve = seed("CVE-2099-1006", 0.10001f, null, null);

        VulnerabilityAlert alert = enrich(cve);

        assertThat(alert.isActionable()).isTrue();
        assertThat(alert.getActionableReason()).isEqualTo(ActionableReason.EPSS_HIGH);
    }

    /* ------------------------------------------------------------------ */
    /* Snapshots and the resolver seam                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void anUnscoredCveGetsANullCvssSnapshotRatherThanZero() {
        Vulnerability unscored = seed("CVE-2099-1007", 0.4f, null, null);
        unscored.setCvssScore(0.0d);

        assertThat(enrich(unscored).getCvssScore()).isNull();

        Vulnerability scored = seed("CVE-2099-1008", 0.4f, null, null);
        scored.setCvssScore(9.8d);

        assertThat(enrich(scored).getCvssScore()).isEqualTo(9.8d);
    }

    @Test
    void theExploitIndexSeamLiftsMaturityAboveNoneWithoutKev() {
        Vulnerability cve = seed(CVE_WITH_PUBLIC_POC, 0.4f, null, null);

        assertThat(enrich(cve).getExploitMaturity()).isEqualTo(ExploitMaturity.POC);
    }

    @Test
    void kevStillWinsOverALowerResolverVerdict() {
        // Same CVE the stub calls POC, now also KEV-listed: max(IN_THE_WILD, POC) = IN_THE_WILD.
        Vulnerability cve = seed(CVE_WITH_PUBLIC_POC, 0.4f, LocalDate.of(2026, 6, 1), "Known");

        assertThat(enrich(cve).getExploitMaturity()).isEqualTo(ExploitMaturity.IN_THE_WILD);
    }

    /* ------------------------------------------------------------------ */
    /* Fix state                                                          */
    /* ------------------------------------------------------------------ */

    @Test
    void fixStateIsUnknownUntilSomethingSuppliesAVersion() {
        Vulnerability cve = seed("CVE-2099-1009", 0.4f, null, null);

        VulnerabilityAlert alert = enrich(cve);

        assertThat(alert.getFixState()).isEqualTo(FixState.UNKNOWN);
        assertThat(alert.getFixedVersions()).isNull();
        assertThat(alert.getFixSource()).isNull();
    }

    @Test
    void aScannerSuppliedVersionMarksTheAlertFixed() {
        Vulnerability cve = seed("CVE-2099-1010", 0.4f, null, null);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        enrichmentService.enrich(alert, " 2.17.1 ");

        assertThat(alert.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(alert.getFixedVersions()).isEqualTo("2.17.1");
        assertThat(alert.getFixSource()).isEqualTo(FixSource.SCANNER);
    }

    @Test
    void reEnrichingWithoutFixInformationLeavesAnEstablishedFixAlone() {
        Vulnerability cve = seed("CVE-2099-1011", 0.4f, null, null);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setFixState(FixState.FIXED);
        alert.setFixedVersions("2.17.1");
        alert.setFixSource(FixSource.OSV);

        enrichmentService.enrich(alert);

        // A KEV ingest must not erase what OSV or a scanner already established.
        assertThat(alert.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(alert.getFixedVersions()).isEqualTo("2.17.1");
        assertThat(alert.getFixSource()).isEqualTo(FixSource.OSV);
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private VulnerabilityAlert enrich(Vulnerability cve) {
        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        enrichmentService.enrich(alert);
        return alert;
    }

    /**
     * Persist a CVE with the KEV / EPSS rows the funnel reads, then hand back a freshly loaded
     * instance so the lazy joins resolve against what is actually in the database.
     *
     * @param epssScore  EPSS probability, or null for "this CVE has no EPSS row"
     * @param kevDueDate CISA deadline, or null for "this CVE is not KEV-listed"
     */
    private Vulnerability seed(String cveId, Float epssScore, LocalDate kevDueDate, String ransomware) {
        if (epssScore != null) {
            EPSS epss = new EPSS();
            epss.setCve(cveId);
            epss.setEpss(epssScore);
            epss.setPercentile(0.97f);
            epss.setDate(LocalDateTime.now());
            epssRepository.save(epss);
        }
        if (kevDueDate != null) {
            KEV kev = new KEV();
            kev.setCveId(cveId);
            kev.setName("Seeded KEV entry");
            kev.setVendor("acme");
            kev.setProduct("widget");
            kev.setAdded(LocalDateTime.now().minusDays(3));
            kev.setDueDate(Date.from(kevDueDate.atStartOfDay(ZoneId.systemDefault()).toInstant()));
            kev.setKnownRansomwareCampaignUse(ransomware);
            kevRepository.save(kev);
        }

        Vulnerability cve = new Vulnerability();
        cve.setId(cveId);
        cve.setDescription("Seeded for the funnel test");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.5d);
        cveRepository.save(cve);

        entityManager.flush();
        entityManager.clear();
        return cveRepository.findById(cveId).orElseThrow();
    }

}
