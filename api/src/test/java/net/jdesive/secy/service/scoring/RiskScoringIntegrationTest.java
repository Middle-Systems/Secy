package net.jdesive.secy.service.scoring;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.correlation.CorrelationService;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.EPSS;
import net.jdesive.secy.persistence.entity.KEV;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.persistence.entity.VexStatement;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.service.EnrichmentService;
import net.jdesive.secy.service.vex.VexResolutionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M1i's highest-risk checkpoint: scoring is written by the right hooks, in the right place, without
 * disturbing {@code actionable}/{@code actionableReason} or the M1f VEX reconcile counts (ROADMAP.md
 * — "M1i — Scoring engine rework").
 */
@SpringBootTest
@Transactional
class RiskScoringIntegrationTest {

    @Autowired
    private CorrelationService correlationService;

    @Autowired
    private EnrichmentService enrichmentService;

    @Autowired
    private RiskScoringService riskScoringService;

    @Autowired
    private VexResolutionService vexResolutionService;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private KEVRepository kevRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private VexStatementRepository vexStatementRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void correlatingWritesRiskScoreModelAndScoredAtWithoutTouchingTheFunnel() {
        Vulnerability cve = cve("CVE-2299-1001", "CRITICAL", 9.8d);
        kev(cve, LocalDate.now().plusDays(10));
        epss(cve, 0.9f);
        advisory("GHSA-risk-1", "npm", "risky-lib-1", "CVE-2299-1001");
        entityManager.flush();
        entityManager.clear();

        Product product = product();
        SBOM sbom = sbomWith(product, component("pkg:npm/risky-lib-1@1.0.0", "risky-lib-1", "1.0.0"));
        correlationService.correlate(reload(sbom));

        VulnerabilityAlert alert = onlyAlert(product);
        assertThat(alert.getRiskScore()).isNotNull().isGreaterThan(0.0);
        assertThat(alert.getRiskScoreModel()).isEqualTo("m1i.1");
        assertThat(alert.getRiskScoredAt()).isNotNull();

        // The funnel is untouched by scoring.
        assertThat(alert.isActionable()).isTrue();
        assertThat(alert.getActionableReason()).isEqualTo(ActionableReason.KEV_AND_EPSS_HIGH);
    }

    @Test
    void aNullCveAlertGetsANullScore() {
        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setCreatedAt(LocalDateTime.now());
        alert.setRiskScore(42.0);
        alert.setRiskScoreModel("stale");

        enrichmentService.enrich(alert);

        assertThat(alert.getRiskScore()).isNull();
        assertThat(alert.getRiskScoreModel()).isNull();
        assertThat(alert.isActionable()).isFalse();
    }

    @Test
    void vexNotAffectedDropsScoreToZeroAndDeactivatingRestoresIt() {
        Vulnerability cve = cve("CVE-2299-2001", "CRITICAL", 9.8d);
        kev(cve, LocalDate.now().plusDays(10));
        epss(cve, 0.9f);
        advisory("GHSA-vex-1", "npm", "vex-lib", "CVE-2299-2001");
        entityManager.flush();
        entityManager.clear();

        Product product = product();
        SBOM sbom = sbomWith(product, component("pkg:npm/vex-lib@1.0.0", "vex-lib", "1.0.0"));
        correlationService.correlate(reload(sbom));

        VulnerabilityAlert before = onlyAlert(product);
        double originalScore = before.getRiskScore();
        LocalDateTime originalScoredAt = before.getRiskScoredAt();
        assertThat(originalScore).isGreaterThan(0.0);

        VexStatement statement = vexStatement(cve.getId(), "npm/vex-lib");
        entityManager.flush();
        entityManager.clear();

        VexResolutionService.VexReconcileSummary summary =
                vexResolutionService.reconcileCves(Tenant.DEFAULT_TENANT_ID, Set.of(cve.getId()));
        assertThat(summary.alertsChanged()).isEqualTo(1);

        entityManager.flush();
        entityManager.clear();
        VulnerabilityAlert afterVex = onlyAlert(product);
        assertThat(afterVex.getRiskScore()).isEqualTo(0.0);
        assertThat(afterVex.getVexStatus()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(afterVex.getRiskScoredAt()).isAfterOrEqualTo(originalScoredAt);
        // The funnel never moved.
        assertThat(afterVex.isActionable()).isTrue();
        assertThat(afterVex.getActionableReason()).isEqualTo(ActionableReason.KEV_AND_EPSS_HIGH);

        VexStatement reloadedStatement = vexStatementRepository.findById(statement.getId()).orElseThrow();
        reloadedStatement.setActive(false);
        vexStatementRepository.save(reloadedStatement);
        entityManager.flush();
        entityManager.clear();

        VexResolutionService.VexReconcileSummary summary2 =
                vexResolutionService.reconcileCves(Tenant.DEFAULT_TENANT_ID, Set.of(cve.getId()));
        assertThat(summary2.alertsChanged()).isEqualTo(1);

        entityManager.flush();
        entityManager.clear();
        VulnerabilityAlert restored = onlyAlert(product);
        assertThat(restored.getRiskScore()).isEqualTo(originalScore);
        assertThat(restored.getVexStatus()).isNull();
    }

    @Test
    void reEnrichAllScoresARowSeededWithNullRiskScore() {
        Vulnerability cve = cve("CVE-2299-3001", "HIGH", 7.5d);
        epss(cve, 0.5f);
        entityManager.flush();
        entityManager.clear();

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cveRepository.findById(cve.getId()).orElseThrow());
        alert.setCreatedAt(LocalDateTime.now());
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.EPSS_HIGH);
        alert.setEpssScore(0.5d);
        alert.setCvssScore(7.5d);
        UUID alertId = alertRepository.save(alert).getId();
        entityManager.flush();
        entityManager.clear();

        int reEnriched = enrichmentService.reEnrichAll();
        assertThat(reEnriched).isGreaterThanOrEqualTo(1);

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.getRiskScore()).isNotNull();
        assertThat(reloaded.getRiskScoreModel()).isEqualTo("m1i.1");
        // Funnel outcome is exactly what a run with scoring stubbed out would produce.
        assertThat(reloaded.isActionable()).isTrue();
        assertThat(reloaded.getActionableReason()).isEqualTo(ActionableReason.EPSS_HIGH);
    }

    @Test
    void rescoreAllIsIdempotent() {
        Vulnerability cve = cve("CVE-2299-4001", "HIGH", 7.5d);
        epss(cve, 0.5f);
        advisory("GHSA-idem-1", "npm", "idem-lib", "CVE-2299-4001");
        entityManager.flush();
        entityManager.clear();

        Product product = product();
        SBOM sbom = sbomWith(product, component("pkg:npm/idem-lib@1.0.0", "idem-lib", "1.0.0"));
        correlationService.correlate(reload(sbom));
        entityManager.flush();
        entityManager.clear();

        IngestResult first = riskScoringService.rescoreAll(JobProgress.NOOP);
        assertThat(first.itemsProcessed()).isGreaterThanOrEqualTo(1);
        entityManager.flush();
        entityManager.clear();

        VulnerabilityAlert after1 = onlyAlert(product);
        LocalDateTime scoredAt1 = after1.getRiskScoredAt();
        Double score1 = after1.getRiskScore();

        IngestResult second = riskScoringService.rescoreAll(JobProgress.NOOP);
        assertThat(second.message()).contains("0 changed");
        entityManager.flush();
        entityManager.clear();

        VulnerabilityAlert after2 = onlyAlert(product);
        assertThat(after2.getRiskScoredAt()).isEqualTo(scoredAt1);
        assertThat(after2.getRiskScore()).isEqualTo(score1);
    }

    /* ------------------------------------------------------------------ */
    /* Helpers (mirrors StagedCorrelationScopeTest)                        */
    /* ------------------------------------------------------------------ */

    private SBOM reload(SBOM sbom) {
        return sbomRepository.findByIdWithComponents(sbom.getId()).orElseThrow();
    }

    private VulnerabilityAlert onlyAlert(Product product) {
        List<VulnerabilityAlert> alerts = alertRepository.findAllByProductIdForCorrelation(product.getId());
        assertThat(alerts).hasSize(1);
        return alerts.get(0);
    }

    private Product product() {
        Product product = new Product();
        product.setName("risk-scoring-" + UUID.randomUUID());
        return productRepository.saveAndFlush(product);
    }

    private static SBOMComponent component(String purl, String name, String version) {
        SBOMComponent component = new SBOMComponent();
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("library");
        return component;
    }

    private SBOM sbomWith(Product product, SBOMComponent... components) {
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        sbom.setUploadDate(LocalDateTime.now());
        for (SBOMComponent component : components) {
            component.setSbom(sbom);
            sbom.getComponents().add(component);
        }
        return sbomRepository.saveAndFlush(sbom);
    }

    private Vulnerability cve(String id, String severity, double cvss) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for RiskScoringIntegrationTest");
        cve.setBaseSeverity(severity);
        cve.setCvssScore(cvss);
        cve.setPublished(LocalDateTime.now().minusDays(10));
        cve.setLastModified(LocalDateTime.now().minusDays(1));
        cve.setVulnStatus("Analyzed");
        return cveRepository.save(cve);
    }

    private void kev(Vulnerability cve, LocalDate dueDate) {
        KEV kev = new KEV();
        kev.setCveId(cve.getId());
        kev.setName("Seeded KEV entry for " + cve.getId());
        kev.setVendor("acme");
        kev.setProduct("widget");
        kev.setAdded(LocalDateTime.now().minusDays(1));
        kev.setRequiredActions("Apply updates.");
        kev.setDueDate(java.sql.Date.valueOf(dueDate));
        kev.setKnownRansomwareCampaignUse("Known");
        kevRepository.save(kev);
    }

    private OsvAdvisory advisory(String osvId, String ecosystem, String packageName, String alias) {
        OsvAdvisory advisory = new OsvAdvisory();
        advisory.setOsvId(osvId);
        advisory.setEcosystem(ecosystem);
        advisory.setPackageName(packageName);
        advisory.setModified(LocalDateTime.now());
        advisory.getAliases().add(alias);

        OsvAffectedRange range = new OsvAffectedRange();
        range.setAdvisory(advisory);
        range.setRangeType("SEMVER");
        range.setIntroduced("0");
        advisory.getRanges().add(range);

        return osvRepository.save(advisory);
    }

    private void epss(Vulnerability cve, float score) {
        EPSS epss = new EPSS();
        epss.setCve(cve.getId());
        epss.setEpss(score);
        epss.setPercentile(0.99f);
        epss.setDate(LocalDateTime.now().minusDays(1));
        epssRepository.save(epss);
    }

    private VexStatement vexStatement(String cveId, String matchKey) {
        VexStatement statement = new VexStatement();
        statement.setDocumentId(UUID.randomUUID());
        statement.setFormat(VexDocumentFormat.OPENVEX);
        statement.setOrigin(VexOrigin.TENANT);
        statement.setAuthor("Seeded test author");
        statement.setAuthorKey("seeded-test-author");
        statement.setActive(true);
        statement.setCveId(cveId);
        statement.setStatus(VexStatus.NOT_AFFECTED);
        statement.setSourceStatus("not_affected");
        statement.setJustification(null);
        statement.setProductRef(matchKey);
        statement.setTargetPurl(null);
        statement.setMatchKey(matchKey);
        statement.setMatchVersion(null);
        statement.setStatementTimestamp(LocalDateTime.now());
        statement.setOrdinal(0);
        return vexStatementRepository.save(statement);
    }

}
