package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.correlation.CorrelationService;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.service.SBOMService;
import net.jdesive.secy.service.sbom.SbomParser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * M1l (ROADMAP.md — "Dependency graph preserved"): {@code GET /actionable/{id}}'s {@code dependency}
 * block, end to end through the real ingest + correlation path, same pattern as {@code
 * RiskScoreAcceptanceTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ActionableDependencyDetailTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SbomParser sbomParser;

    @Autowired
    private SBOMService sbomService;

    @Autowired
    private CorrelationService correlationService;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private AssetRepository assetRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Test
    @WithMockUser
    void transitiveComponentReportsItsThreeHopPathAssetAlertReportsNull() throws Exception {
        Vulnerability cve = cve("CVE-2299-6001", "HIGH", 7.5d);
        advisory("GHSA-dep-detail-a", "npm", "dep-detail-a", cve.getId());
        advisory("GHSA-dep-detail-b", "npm", "dep-detail-b", cve.getId());
        advisory("GHSA-dep-detail-asset", "npm", "dep-detail-asset", cve.getId());
        entityManager.flush();
        entityManager.clear();

        Product product = product();
        String json = """
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "component": { "type": "application", "bom-ref": "root", "name": "root" } },
                  "components": [
                    { "type": "library", "bom-ref": "a", "name": "dep-detail-a", "version": "1.0.0", "purl": "pkg:npm/dep-detail-a@1.0.0" },
                    { "type": "library", "bom-ref": "b", "name": "dep-detail-b", "version": "1.0.0", "purl": "pkg:npm/dep-detail-b@1.0.0" }
                  ],
                  "dependencies": [
                    { "ref": "root", "dependsOn": [ "a" ] },
                    { "ref": "a", "dependsOn": [ "b" ] }
                  ] }
                """;
        NormalizedSbom document = sbomParser.parse(mapper.readTree(json));
        SBOM placeholder = sbomService.createPlaceholder(product, document, "1.0.0", json, null,
                SbomIngestionSource.MANUAL_UPLOAD, null);
        sbomService.ingestDocument(placeholder, document, JobProgress.NOOP);
        entityManager.flush();
        entityManager.clear();

        SBOM sbom = sbomRepository.findByIdWithComponents(placeholder.getId()).orElseThrow();
        correlationService.correlate(sbom);
        entityManager.flush();
        entityManager.clear();

        List<VulnerabilityAlert> alerts = alertRepository.findAllByProductIdForCorrelation(product.getId());
        VulnerabilityAlert bAlert = alerts.stream()
                .filter(a -> "dep-detail-b".equals(a.getComponent().getName())).findFirst().orElseThrow();

        mockMvc.perform(get("/actionable/{id}", bAlert.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dependency.depth").value("TRANSITIVE"))
                .andExpect(jsonPath("$.dependency.distance").value(2))
                .andExpect(jsonPath("$.dependency.path.length()").value(3))
                .andExpect(jsonPath("$.dependency.path[0].bomRef").value("root"))
                .andExpect(jsonPath("$.dependency.path[0].name").value("root"))
                .andExpect(jsonPath("$.dependency.path[1].bomRef").value("a"))
                .andExpect(jsonPath("$.dependency.path[1].name").value("dep-detail-a"))
                .andExpect(jsonPath("$.dependency.path[2].bomRef").value("b"))
                .andExpect(jsonPath("$.dependency.path[2].name").value("dep-detail-b"));

        // Asset alert for the same CVE -- dependency is null (no SBOM component).
        Asset asset = new Asset();
        asset.setType(AssetType.CONTAINER_IMAGE);
        asset.setName("asset-" + UUID.randomUUID());
        asset.setStatus("ACTIVE");
        asset = assetRepository.save(asset);

        AssetComponent ac = new AssetComponent();
        ac.setAsset(asset);
        ac.setName("dep-detail-asset");
        ac.setVersion("1.0.0");
        ac.setPurl("pkg:npm/dep-detail-asset@1.0.0");
        ac.setEcosystem("npm");
        ac.setPresentInLastScan(true);
        asset.getComponents().add(ac);
        assetRepository.save(asset);
        entityManager.flush();
        entityManager.clear();

        Asset reloaded = assetRepository.findById(asset.getId()).orElseThrow();
        correlationService.correlate(reloaded, List.of());
        entityManager.flush();
        entityManager.clear();

        List<VulnerabilityAlert> assetAlerts = alertRepository.findAllByAssetIdForCorrelation(asset.getId());
        assertThat(assetAlerts).hasSize(1);

        mockMvc.perform(get("/actionable/{id}", assetAlerts.get(0).getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dependency").doesNotExist());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private Product product() {
        Product product = new Product();
        product.setName("dep-detail-" + UUID.randomUUID());
        return productRepository.saveAndFlush(product);
    }

    private Vulnerability cve(String id, String severity, double cvss) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for ActionableDependencyDetailTest");
        cve.setBaseSeverity(severity);
        cve.setCvssScore(cvss);
        cve.setPublished(LocalDateTime.now().minusDays(10));
        cve.setLastModified(LocalDateTime.now().minusDays(1));
        cve.setVulnStatus("Analyzed");
        return cveRepository.save(cve);
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

}
