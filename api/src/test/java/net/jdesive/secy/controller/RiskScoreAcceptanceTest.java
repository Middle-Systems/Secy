package net.jdesive.secy.controller;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.correlation.CorrelationService;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.EPSS;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.KEV;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Vulnerability;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The M1i acceptance bar (ROADMAP.md — "Scoring engine rework"): a KEV-listed deployed finding
 * outranks the same CVE, same component, source-only in another product — by score, not recency —
 * while {@code actionable}/{@code actionableReason} and the default EPSS sort stay exactly as they
 * were before M1i.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class RiskScoreAcceptanceTest {

    private static final String CVE_ID = "CVE-2199-9001";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CorrelationService correlationService;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private KEVRepository kevRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Test
    @WithMockUser
    void kevListedDeployedOutranksTheSameCveSourceOnly() throws Exception {
        cve(CVE_ID, "CRITICAL", 9.8d);
        kev(CVE_ID, LocalDate.now().plusDays(30));
        epss(CVE_ID, 0.94f, 0.99f);
        advisory("GHSA-risky-1", "npm", "risky-lib", CVE_ID, "0", "2.0.0");
        // The exact gotcha ActionableControllerTest documents: KEV/EPSS live behind an unbuffered
        // lazy @OneToOne, so the persistence context must be cleared before correlation reads it back.
        entityManager.flush();
        entityManager.clear();

        Product deployedCo = product("Deployed Co");
        SBOM deployedSbom = sbomInProduct(deployedCo, SbomLifecycleStage.DEPLOYED,
                component("pkg:npm/risky-lib@1.0.0", "risky-lib", "1.0.0"));
        correlationService.correlate(reload(deployedSbom));

        Product sourceCo = product("Source Co");
        SBOM sourceSbom = sbomInProduct(sourceCo, SbomLifecycleStage.SOURCE,
                component("pkg:npm/risky-lib@1.0.0", "risky-lib", "1.0.0"));
        correlationService.correlate(reload(sourceSbom));

        VulnerabilityAlert deployedAlert = onlyAlertFor(deployedCo);
        VulnerabilityAlert sourceAlert = onlyAlertFor(sourceCo);

        // Source correlated after Deployed, so it has the newer createdAt -- proving score, not
        // recency, is what orders the default listing.
        assertThat(sourceAlert.getCreatedAt()).isAfterOrEqualTo(deployedAlert.getCreatedAt());

        assertThat(deployedAlert.getActionableReason()).isEqualTo(ActionableReason.KEV_AND_EPSS_HIGH);
        assertThat(sourceAlert.getActionableReason()).isEqualTo(ActionableReason.KEV_AND_EPSS_HIGH);
        assertThat(deployedAlert.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(sourceAlert.getFixState()).isEqualTo(FixState.FIXED);

        assertThat(deployedAlert.getRiskScore()).isEqualTo(92.8);
        assertThat(sourceAlert.getRiskScore()).isEqualTo(55.7);

        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].productName").value("Deployed Co"))
                .andExpect(jsonPath("$.content[0].riskScore").value(92.8))
                .andExpect(jsonPath("$.content[1].productName").value("Source Co"))
                .andExpect(jsonPath("$.content[1].riskScore").value(55.7));

        mockMvc.perform(get("/actionable").param("rankBy", "SCORE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].productName").value("Deployed Co"))
                .andExpect(jsonPath("$.content[1].productName").value("Source Co"));

        mockMvc.perform(get("/actionable/{id}", sourceAlert.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.riskScore").value(55.7))
                .andExpect(jsonPath("$.riskScoreBreakdown.current").value(true))
                .andExpect(jsonPath("$.riskScoreBreakdown.factors[4].input").value("LIFECYCLE_PRESENCE"))
                .andExpect(jsonPath("$.riskScoreBreakdown.factors[4].value").value("SOURCE"))
                .andExpect(jsonPath("$.riskScoreBreakdown.factors[4].weight").value(0.6))
                .andExpect(jsonPath("$.riskScoreBreakdown.factors[4].points").value(-39.1))
                .andExpect(jsonPath("$.riskScoreBreakdown.factors[6].input").value("DEPENDENCY_DEPTH"))
                .andExpect(jsonPath("$.riskScoreBreakdown.factors[6].available").value(false));
    }

    @Test
    @WithMockUser
    void anUnstagedLegacySbomScoresTheSameAsDeployed() throws Exception {
        String cveId = "CVE-2199-9002";
        cve(cveId, "CRITICAL", 9.8d);
        kev(cveId, LocalDate.now().plusDays(30));
        epss(cveId, 0.94f, 0.99f);
        advisory("GHSA-risky-2", "npm", "legacy-lib", cveId, "0", "2.0.0");
        entityManager.flush();
        entityManager.clear();

        Product deployedCo = product("Deployed Legacy Co");
        SBOM deployedSbom = sbomInProduct(deployedCo, SbomLifecycleStage.DEPLOYED,
                component("pkg:npm/legacy-lib@1.0.0", "legacy-lib", "1.0.0"));
        correlationService.correlate(reload(deployedSbom));

        Product legacyCo = product("Legacy Co");
        SBOM legacySbom = sbomInProduct(legacyCo, null,
                component("pkg:npm/legacy-lib@1.0.0", "legacy-lib", "1.0.0"));
        correlationService.correlate(reload(legacySbom));

        VulnerabilityAlert deployedAlert = onlyAlertFor(deployedCo);
        VulnerabilityAlert legacyAlert = onlyAlertFor(legacyCo);

        assertThat(legacyAlert.getRiskScore()).isEqualTo(deployedAlert.getRiskScore());
        assertThat(legacyAlert.getRiskScore()).isEqualTo(92.8);
    }

    /* ------------------------------------------------------------------ */
    /* Helpers (mirrors StagedCorrelationScopeTest / ActionableControllerTest) */
    /* ------------------------------------------------------------------ */

    private SBOM reload(SBOM sbom) {
        return sbomRepository.findByIdWithComponents(sbom.getId()).orElseThrow();
    }

    private VulnerabilityAlert onlyAlertFor(Product product) {
        List<VulnerabilityAlert> alerts = alertRepository.findAllByProductIdForCorrelation(product.getId());
        assertThat(alerts).hasSize(1);
        return alerts.get(0);
    }

    private Product product(String name) {
        Product product = new Product();
        product.setName(name);
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

    private SBOM sbomInProduct(Product product, SbomLifecycleStage stage, SBOMComponent... components) {
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.5");
        sbom.setVersion(1);
        sbom.setProductVersion("1.0.0");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        sbom.setUploadDate(LocalDateTime.now());
        sbom.setLifecycleStage(stage);
        for (SBOMComponent component : components) {
            component.setSbom(sbom);
            sbom.getComponents().add(component);
        }
        return sbomRepository.saveAndFlush(sbom);
    }

    private Vulnerability cve(String id, String severity, double cvss) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for RiskScoreAcceptanceTest");
        cve.setBaseSeverity(severity);
        cve.setCvssScore(cvss);
        cve.setPublished(LocalDateTime.now().minusDays(10));
        cve.setLastModified(LocalDateTime.now().minusDays(1));
        cve.setVulnStatus("Analyzed");
        return cveRepository.save(cve);
    }

    private void kev(String cveId, LocalDate dueDate) {
        KEV kev = new KEV();
        kev.setCveId(cveId);
        kev.setName("Seeded KEV entry for " + cveId);
        kev.setVendor("acme");
        kev.setProduct("widget");
        kev.setAdded(LocalDateTime.now().minusDays(1));
        kev.setRequiredActions("Apply updates per vendor instructions.");
        kev.setDueDate(Date.from(dueDate.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        kev.setKnownRansomwareCampaignUse("Known");
        kevRepository.save(kev);
    }

    private void epss(String cveId, float score, float percentile) {
        EPSS epss = new EPSS();
        epss.setCve(cveId);
        epss.setEpss(score);
        epss.setPercentile(percentile);
        epss.setDate(LocalDateTime.now().minusDays(1));
        epssRepository.save(epss);
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

}
