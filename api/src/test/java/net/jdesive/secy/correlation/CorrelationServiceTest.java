package net.jdesive.secy.correlation;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The correlation engine's behavioural contract, at a finer grain than the golden set.
 *
 * <p>The golden set proves the engine agrees with hand-verified answers on whole SBOMs. These prove
 * the rules underneath it: which path runs, what happens when OSV knows a CVE the NVD mirror does
 * not, and that a repeated scan converges instead of accumulating rows.
 */
@SpringBootTest
@Transactional
class CorrelationServiceTest {

    @Autowired
    private CorrelationService correlationService;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @PersistenceContext
    private EntityManager entityManager;

    /* ------------------------------------------------------------------ */
    /* Path selection                                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void osvCoverageWithoutAHitSuppressesTheCpeFallbackEntirely() {
        // OSV knows this package and says this version is fine. A wildcard CPE row that would match
        // every version of it exists too. The whole point of the OSV-primary design is that the
        // clean verdict wins — this is the false positive the old engine produced.
        cve("CVE-2099-3001", 0.9f);
        cpeRow("CVE-2099-3001", "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", null, null);
        advisory("GHSA-covered", "npm", "widget", "CVE-2099-3001", "0", "1.0.0");

        UUID sbomId = sbom("pkg:npm/widget@2.0.0", "widget", "2.0.0");
        correlate(sbomId);

        assertThat(alertsFor(sbomId)).isEmpty();
    }

    @Test
    void aPackageOsvHasNeverHeardOfFallsThroughToCpe() {
        cve("CVE-2099-3002", 0.9f);
        cpeRow("CVE-2099-3002", "cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*", "1.0.0", "3.0.0");

        UUID sbomId = sbom("pkg:npm/gadget@2.0.0", "gadget", "2.0.0");
        correlate(sbomId);

        List<VulnerabilityAlert> alerts = alertsFor(sbomId);
        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).getFixSource()).isEqualTo(FixSource.CPE_RANGE);
        assertThat(alerts.get(0).getFixedVersions()).isEqualTo("3.0.0");
    }

    @Test
    void aComponentWithNoPurlStillCorrelatesThroughCpe() {
        cve("CVE-2099-3003", 0.9f);
        cpeRow("CVE-2099-3003", "cpe:2.3:a:acme:legacyd:*:*:*:*:*:*:*:*", "1.0", "2.0");

        UUID sbomId = sbom(null, "legacyd", "1.5");
        correlate(sbomId);

        List<VulnerabilityAlert> alerts = alertsFor(sbomId);
        assertThat(alerts).hasSize(1);
        // No PURL means no type, no vendor convention, and therefore only a name guess.
        assertThat(alerts.get(0).getMatchConfidence()).isEqualTo(MatchConfidence.HEURISTIC);
    }

    /* ------------------------------------------------------------------ */
    /* Resolution gaps                                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void anAdvisoryWhoseCveTheNvdMirrorLacksIsSkippedRatherThanHalfStored() {
        // OSV moves faster than the NVD mirror. An alert with no Vulnerability row could not be
        // enriched, sorted or explained, so it waits for the next scan.
        advisory("GHSA-ahead-of-nvd", "npm", "ahead", "CVE-2099-3004", "0", "9.9.9");

        UUID sbomId = sbom("pkg:npm/ahead@1.0.0", "ahead", "1.0.0");
        CorrelationService.CorrelationSummary summary = correlate(sbomId);

        assertThat(alertsFor(sbomId)).isEmpty();
        assertThat(summary.skippedUnknownCve()).isEqualTo(1);
        assertThat(summary.osvCovered()).isEqualTo(1);
    }

    @Test
    void anAdvisoryWithNoCveAliasIsSkipped() {
        // GHSA-only advisories cannot enter a CVE-keyed funnel. Documented gap, not a silent drop.
        advisory("GHSA-no-cve-alias", "npm", "ghsaonly", "GHSA-no-cve-alias", "0", "2.0.0");

        UUID sbomId = sbom("pkg:npm/ghsaonly@1.0.0", "ghsaonly", "1.0.0");
        correlate(sbomId);

        assertThat(alertsFor(sbomId)).isEmpty();
    }

    @Test
    void aWithdrawnAdvisoryRaisesNothing() {
        cve("CVE-2099-3005", 0.9f);
        OsvAdvisory withdrawn = advisory("GHSA-withdrawn", "npm", "retracted", "CVE-2099-3005", "0", "2.0.0");
        withdrawn.setWithdrawn(LocalDateTime.now());
        osvRepository.save(withdrawn);

        UUID sbomId = sbom("pkg:npm/retracted@1.0.0", "retracted", "1.0.0");
        correlate(sbomId);

        assertThat(alertsFor(sbomId)).isEmpty();
    }

    /* ------------------------------------------------------------------ */
    /* Idempotence                                                        */
    /* ------------------------------------------------------------------ */

    @Test
    void rescanningTheSameSbomUpdatesInPlaceInsteadOfDuplicating() {
        cve("CVE-2099-3006", 0.9f);
        advisory("GHSA-stable", "npm", "stable", "CVE-2099-3006", "0", "2.0.0");
        UUID sbomId = sbom("pkg:npm/stable@1.0.0", "stable", "1.0.0");

        CorrelationService.CorrelationSummary first = correlate(sbomId);
        assertThat(first.created()).isEqualTo(1);
        UUID alertId = alertsFor(sbomId).get(0).getId();

        CorrelationService.CorrelationSummary second = correlate(sbomId);

        assertThat(second.created()).isZero();
        assertThat(second.updated()).isEqualTo(1);
        assertThat(alertsFor(sbomId))
                .singleElement()
                .satisfies(a -> assertThat(a.getId()).isEqualTo(alertId));
    }

    @Test
    void confidenceIsRecordedOnEveryPath() {
        cve("CVE-2099-3007", 0.9f);
        // An enumerated versions[] entry: the advisory names the version the SBOM declares.
        OsvAdvisory exact = advisory("GHSA-exact", "npm", "pinned", "CVE-2099-3007", "0", "2.0.0");
        exact.getVersions().add("1.0.0");
        osvRepository.save(exact);

        UUID sbomId = sbom("pkg:npm/pinned@1.0.0", "pinned", "1.0.0");
        correlate(sbomId);

        assertThat(alertsFor(sbomId))
                .singleElement()
                .satisfies(a -> {
                    assertThat(a.getMatchConfidence()).isEqualTo(MatchConfidence.EXACT);
                    assertThat(a.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
                    assertThat(a.getLastSeenAt()).isNotNull();
                });
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private CorrelationService.CorrelationSummary correlate(UUID sbomId) {
        entityManager.flush();
        entityManager.clear();
        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        CorrelationService.CorrelationSummary summary = correlationService.correlate(sbom);
        entityManager.flush();
        return summary;
    }

    private List<VulnerabilityAlert> alertsFor(UUID sbomId) {
        return alertRepository.findAllBySbomIdForCorrelation(sbomId);
    }

    private void cve(String id, float epssScore) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for a correlation test");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.5d);
        cveRepository.save(cve);

        EPSS epss = new EPSS();
        epss.setCve(id);
        epss.setEpss(epssScore);
        epss.setPercentile(0.99f);
        epss.setDate(LocalDateTime.now());
        epssRepository.save(epss);
    }

    private void cpeRow(String cveId, String criteria, String startIncluding, String endExcluding) {
        Vulnerability cve = cveRepository.findById(cveId).orElseThrow();

        CPEOperator operator = new CPEOperator();
        operator.setOperator("OR");
        operator.setNegate(false);
        operator.setCve(cve);

        CPEMatch match = new CPEMatch();
        match.setCriteria(criteria);
        match.setVulnerable(true);
        match.setMatchCriteriaId(UUID.randomUUID().toString());
        match.setVersionStartIncluding(startIncluding);
        match.setVersionEndExcluding(endExcluding);
        match.setOperator(operator);

        operator.getCpeMatches().add(match);
        cve.getCpeOperators().add(operator);
        cveRepository.save(cve);
    }

    private OsvAdvisory advisory(String osvId, String ecosystem, String packageName, String alias,
                                 String introduced, String fixed) {
        OsvAdvisory advisory = new OsvAdvisory();
        advisory.setOsvId(osvId);
        advisory.setEcosystem(ecosystem);
        advisory.setPackageName(packageName);
        advisory.setModified(LocalDateTime.now());
        advisory.getAliases().add(alias);

        OsvAffectedRange range = new OsvAffectedRange();
        range.setAdvisory(advisory);
        range.setRangeType("SEMVER");
        range.setIntroduced(introduced);
        range.setFixed(fixed);
        advisory.getRanges().add(range);

        return osvRepository.save(advisory);
    }

    private UUID sbom(String purl, String name, String version) {
        Product product = new Product();
        product.setName("correlation-test-" + UUID.randomUUID());
        product = productRepository.save(product);

        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.5");
        sbom.setVersion(1);
        sbom.setProductVersion("1.0.0");
        sbom.setActive(true);
        sbom.setStatus("PROCESSING");
        sbom.setUploadDate(LocalDateTime.now());

        SBOMComponent component = new SBOMComponent();
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("library");
        component.setSbom(sbom);
        sbom.getComponents().add(component);

        return sbomRepository.saveAndFlush(sbom).getId();
    }

}
