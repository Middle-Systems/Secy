package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.TriageEventRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Vulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.function.Consumer;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /products/{id}/risk-score}, {@code GET /assets/{id}/risk-score},
 * {@code GET /risk-score/model} and {@code POST /risk-score/rescore} (M1i, ROADMAP.md — "Scoring
 * engine rework").
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class RiskScoreControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private TriageEventRepository triageEventRepository;

    @Autowired
    private JobRepository jobRepository;

    private Product product;
    private UUID topAlertId;
    private Vulnerability seededCve;

    @BeforeEach
    void seed() {
        triageEventRepository.deleteAll();
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();

        product = product("Rollup Co");
        SBOMComponent top = component("top-lib", "1.0.0", "pkg:npm/top-lib@1.0.0");
        SBOMComponent vexExcluded = component("vex-lib", "1.0.0", "pkg:npm/vex-lib@1.0.0");
        SBOMComponent resolvedExcluded = component("resolved-lib", "1.0.0", "pkg:npm/resolved-lib@1.0.0");
        SBOMComponent autoResolvedExcluded = component("stale-lib", "1.0.0", "pkg:npm/stale-lib@1.0.0");
        SBOMComponent nonActionable = component("quiet-lib", "1.0.0", "pkg:npm/quiet-lib@1.0.0");
        SBOMComponent belowMinScore = component("mid-lib", "1.0.0", "pkg:npm/mid-lib@1.0.0");
        SBOMComponent evilLib = component("evil-lib", "1.0.0", "pkg:npm/evil-lib@1.0.0");
        sbom(product, top, vexExcluded, resolvedExcluded, autoResolvedExcluded, nonActionable, belowMinScore, evilLib);

        Vulnerability cve = cve("CVE-2399-1001");
        seededCve = cve;

        topAlertId = alert(cve, top, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.5d);
            a.setRiskScore(92.8);
            a.setRiskScoreModel("m1i.1");
        });
        alert(cve, vexExcluded, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.5d);
            a.setRiskScore(99.0);
            a.setRiskScoreModel("m1i.1");
            a.setVexStatus(VexStatus.NOT_AFFECTED);
        });
        alert(cve, resolvedExcluded, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.5d);
            a.setRiskScore(99.0);
            a.setRiskScoreModel("m1i.1");
            a.setTriageState(TriageState.RESOLVED);
        });
        alert(cve, autoResolvedExcluded, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.5d);
            a.setRiskScore(99.0);
            a.setRiskScoreModel("m1i.1");
            a.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
        });
        alert(cve, nonActionable, a -> {
            a.setActionable(false);
            a.setCvssScore(9.0d);
            a.setRiskScore(99.0);
            a.setRiskScoreModel("m1i.1");
        });
        alert(cve, belowMinScore, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.4d);
            a.setRiskScore(55.7);
            a.setRiskScoreModel("m1i.1");
        });

        CompromiseFinding finding = new CompromiseFinding();
        finding.setType(CompromiseType.MALICIOUS_PACKAGE);
        finding.setConfidence(CompromiseConfidence.CONFIRMED);
        finding.setSource("Seeded feed");
        finding.setIocId("MAL-2399-0001");
        finding.setMatchedOn("pkg:npm/evil-lib@1.0.0");
        finding.setComponent(evilLib);
        findingRepository.save(finding);
    }

    @Test
    @WithMockUser
    void productRollupIsTheMaximumWithTheRightTopFindingAndCompromiseCountedSeparately() throws Exception {
        mockMvc.perform(get("/products/{id}/risk-score", product.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scopeType").value("PRODUCT"))
                .andExpect(jsonPath("$.score").value(92.8))
                .andExpect(jsonPath("$.topFindingId").value(topAlertId.toString()))
                .andExpect(jsonPath("$.compromiseFindingCount").value(1))
                .andExpect(jsonPath("$.model").value("m1i.1"));
    }

    @Test
    @WithMockUser
    void anAssetLinkedToTheProductAppearsOnlyInItsOwnRollup() throws Exception {
        Asset asset = new Asset();
        asset.setType(AssetType.CONTAINER_IMAGE);
        asset.setName("linked-asset:latest");
        asset.setProduct(product);
        AssetComponent assetComponent = new AssetComponent();
        assetComponent.setName("asset-lib");
        assetComponent.setVersion("1.0.0");
        assetComponent.setPurl("pkg:npm/asset-lib@1.0.0");
        assetComponent.setAsset(asset);
        asset.getComponents().add(assetComponent);
        assetRepository.saveAndFlush(asset);

        VulnerabilityAlert assetAlert = new VulnerabilityAlert();
        assetAlert.setVulnerability(seededCve);
        assetAlert.setAssetComponent(assetComponent);
        assetAlert.setCreatedAt(LocalDateTime.now());
        assetAlert.setActionable(true);
        assetAlert.setActionableReason(ActionableReason.EPSS_HIGH);
        assetAlert.setRiskScore(97.0);
        assetAlert.setRiskScoreModel("m1i.1");
        alertRepository.save(assetAlert);

        mockMvc.perform(get("/assets/{id}/risk-score", asset.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scopeType").value("ASSET"))
                .andExpect(jsonPath("$.score").value(97.0));

        // The product rollup is unaffected -- still 92.8, not the asset's 97.0.
        mockMvc.perform(get("/products/{id}/risk-score", product.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").value(92.8));
    }

    @Test
    @WithMockUser
    void aProductWithOnlyUnscoredRowsHasANullScoreAndAPositiveUnscoredCount() throws Exception {
        Product unscored = product("Unscored Co");
        SBOMComponent c = component("unscored-lib", "1.0.0", "pkg:npm/unscored-lib@1.0.0");
        sbom(unscored, c);
        alert(seededCve, c, a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.5d);
        });

        mockMvc.perform(get("/products/{id}/risk-score", unscored.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").doesNotExist())
                .andExpect(jsonPath("$.findingCount").value(1))
                .andExpect(jsonPath("$.unscoredFindingCount").value(1));
    }

    @Test
    @WithMockUser
    void unknownScopeIdsAre404() throws Exception {
        mockMvc.perform(get("/products/{id}/risk-score", UUID.randomUUID()))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/assets/{id}/risk-score", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser
    void modelEndpointReportsTheDefaultWeights() throws Exception {
        mockMvc.perform(get("/risk-score/model"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.modelVersion").value("m1i.1"))
                .andExpect(jsonPath("$.lifecycleFactor.SOURCE").value(0.6));
    }

    @Test
    @WithMockUser
    void rescoreIsQueuedAsASingletonJob() throws Exception {
        String firstBody = mockMvc.perform(post("/risk-score/rescore"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("RISK_RESCORE"))
                .andReturn().getResponse().getContentAsString();

        mockMvc.perform(post("/risk-score/rescore"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("RISK_RESCORE"));

        // Still exactly one QUEUED/RUNNING RISK_RESCORE row -- the second call returned the same job.
        long active = jobRepository.findAll().stream()
                .filter(j -> j.getType() == net.jdesive.secy.persistence.entity.JobType.RISK_RESCORE)
                .filter(j -> j.getStatus() == JobStatus.QUEUED || j.getStatus() == JobStatus.RUNNING)
                .count();
        org.assertj.core.api.Assertions.assertThat(active).isEqualTo(1);
        org.assertj.core.api.Assertions.assertThat(firstBody).contains("RISK_RESCORE");
    }

    @Test
    @WithMockUser
    void minScoreExcludesLowerScoredRowsAndEveryCompromiseRow() throws Exception {
        mockMvc.perform(get("/actionable").param("productId", product.getId().toString()).param("minScore", "60"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].id").value(topAlertId.toString()))
                .andExpect(jsonPath("$.content[?(@.itemType == 'COMPROMISE')]", hasSize(0)));
    }

    @Test
    @WithMockUser
    void invalidRankByIsABadRequest() throws Exception {
        mockMvc.perform(get("/actionable").param("rankBy", "bogus"))
                .andExpect(status().isBadRequest());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private Product product(String name) {
        Product product = new Product();
        product.setName(name);
        return productRepository.saveAndFlush(product);
    }

    private static SBOMComponent component(String name, String version, String purl) {
        SBOMComponent component = new SBOMComponent();
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("library");
        return component;
    }

    private void sbom(Product product, SBOMComponent... components) {
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        for (SBOMComponent component : components) {
            component.setSbom(sbom);
            sbom.getComponents().add(component);
        }
        sbomRepository.save(sbom);
    }

    private Vulnerability cve(String id) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for RiskScoreControllerTest");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.5d);
        cve.setPublished(LocalDateTime.now().minusDays(10));
        cve.setLastModified(LocalDateTime.now().minusDays(1));
        cve.setVulnStatus("Analyzed");
        return cveRepository.save(cve);
    }

    private UUID alert(Vulnerability cve, SBOMComponent component, Consumer<VulnerabilityAlert> customize) {
        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setCreatedAt(LocalDateTime.now());
        customize.accept(alert);
        return alertRepository.save(alert).getId();
    }

}
