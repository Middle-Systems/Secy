package net.jdesive.secy.service.scoring;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.correlation.CorrelationService;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.model.scoring.ScoreFactor;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.DependencyDepth;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.service.SBOMService;
import net.jdesive.secy.service.sbom.SbomParser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.offset;

/**
 * M1l's real payoff (ROADMAP.md — "Dependency graph preserved"): a DIRECT component and a
 * TRANSITIVE component of the same real ingested SBOM, vulnerable to the same CVE, score 10% apart
 * through the real M1i weight — not just the pure {@code RiskScorer} unit test. Seeding mirrors
 * {@code RiskScoringIntegrationTest}/{@code RiskScoreAcceptanceTest}.
 */
@SpringBootTest
@Transactional
class DependencyDepthScoringIntegrationTest {

    private final ObjectMapper mapper = new ObjectMapper();

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
    void directComponentScoresHigherThanTransitiveComponentForTheSameCve() throws Exception {
        Vulnerability cve = cve("CVE-2299-5001", "HIGH", 7.5d);
        advisory("GHSA-dep-a", "npm", "dep-a", cve.getId());
        advisory("GHSA-dep-b", "npm", "dep-b", cve.getId());
        entityManager.flush();
        entityManager.clear();

        Product product = product();
        String json = """
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "component": { "type": "application", "bom-ref": "root", "name": "root" } },
                  "components": [
                    { "type": "library", "bom-ref": "a", "name": "dep-a", "version": "1.0.0", "purl": "pkg:npm/dep-a@1.0.0" },
                    { "type": "library", "bom-ref": "b", "name": "dep-b", "version": "1.0.0", "purl": "pkg:npm/dep-b@1.0.0" }
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
        assertThat(alerts).hasSize(2);

        VulnerabilityAlert directAlert = alerts.stream()
                .filter(a -> "dep-a".equals(a.getComponent().getName())).findFirst().orElseThrow();
        VulnerabilityAlert transitiveAlert = alerts.stream()
                .filter(a -> "dep-b".equals(a.getComponent().getName())).findFirst().orElseThrow();

        assertThat(directAlert.getComponent().getDependencyDepth()).isEqualTo(DependencyDepth.DIRECT);
        assertThat(transitiveAlert.getComponent().getDependencyDepth()).isEqualTo(DependencyDepth.TRANSITIVE);

        assertThat(directAlert.getRiskScore()).isNotNull();
        assertThat(transitiveAlert.getRiskScore()).isNotNull();

        double directScore = directAlert.getRiskScore();
        double transitiveScore = transitiveAlert.getRiskScore();
        assertThat(transitiveScore).isLessThan(directScore);
        // RiskScorer step 7 multiplies by 0.9 for TRANSITIVE vs 1.0 for DIRECT -- same running score
        // up to that step, so the ratio should land within rounding of exactly 0.9.
        assertThat(transitiveScore).isCloseTo(directScore * 0.9, offset(0.5));

        RiskScoreInputs directInputs = RiskScoreInputs.from(directAlert);
        RiskScoreInputs transitiveInputs = RiskScoreInputs.from(transitiveAlert);
        ScoreFactor directFactor = RiskScorer.score(directInputs, ScoringWeights.DEFAULT).factors().get(6);
        ScoreFactor transitiveFactor = RiskScorer.score(transitiveInputs, ScoringWeights.DEFAULT).factors().get(6);
        assertThat(directFactor.value()).isEqualTo("DIRECT");
        assertThat(directFactor.available()).isTrue();
        assertThat(directFactor.weight()).isCloseTo(1.0, offset(0.0001));
        assertThat(transitiveFactor.value()).isEqualTo("TRANSITIVE");
        assertThat(transitiveFactor.available()).isTrue();
        assertThat(transitiveFactor.weight()).isCloseTo(0.9, offset(0.0001));
    }

    @Test
    void assetComponentAlertForTheSameCveStaysUnknown() {
        Vulnerability cve = cve("CVE-2299-5002", "HIGH", 7.5d);
        advisory("GHSA-dep-asset", "npm", "dep-asset", cve.getId());
        entityManager.flush();
        entityManager.clear();

        Asset asset = new Asset();
        asset.setType(AssetType.CONTAINER_IMAGE);
        asset.setName("asset-" + UUID.randomUUID());
        asset.setStatus("ACTIVE");
        asset = assetRepository.save(asset);

        AssetComponent ac = new AssetComponent();
        ac.setAsset(asset);
        ac.setName("dep-asset");
        ac.setVersion("1.0.0");
        ac.setPurl("pkg:npm/dep-asset@1.0.0");
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

        List<VulnerabilityAlert> alerts = alertRepository.findAllByAssetIdForCorrelation(asset.getId());
        assertThat(alerts).hasSize(1);
        VulnerabilityAlert alert = alerts.get(0);
        assertThat(alert.getComponent()).isNull();
        assertThat(alert.getAssetComponent()).isNotNull();

        RiskScoreInputs inputs = RiskScoreInputs.from(alert);
        assertThat(inputs.depth()).isEqualTo(DependencyDepth.UNKNOWN);
        ScoreFactor factor = RiskScorer.score(inputs, ScoringWeights.DEFAULT).factors().get(6);
        assertThat(factor.available()).isFalse();
    }

    @Test
    void dependencyDepthOfMapsNullComponentDepthToUnknown() {
        VulnerabilityAlert alert = new VulnerabilityAlert();
        SBOMComponent component = new SBOMComponent();
        component.setName("no-depth-yet");
        alert.setComponent(component);

        assertThat(RiskScoreInputs.dependencyDepthOf(alert)).isEqualTo(DependencyDepth.UNKNOWN);
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private Product product() {
        Product product = new Product();
        product.setName("dep-depth-scoring-" + UUID.randomUUID());
        return productRepository.saveAndFlush(product);
    }

    private Vulnerability cve(String id, String severity, double cvss) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for DependencyDepthScoringIntegrationTest");
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
