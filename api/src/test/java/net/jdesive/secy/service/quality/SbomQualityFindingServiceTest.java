package net.jdesive.secy.service.quality;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.SbomQualityFindingRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.SbomQualityFinding;
import net.jdesive.secy.service.SBOMService;
import net.jdesive.secy.service.sbom.SbomParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link SbomQualityFindingService#reconcileForSbom}, driven through the real
 * {@code SBOMService.createPlaceholder}/{@code ingestDocument} path so scoring actually runs.
 *
 * <p><b>Deliberately not {@code @Transactional}</b> — same reasoning as
 * {@code QuantumFindingServiceTest}: {@code reconcileForSbom} is {@code REQUIRES_NEW}, which would
 * suspend a test's own uncommitted transaction and see none of its fixtures under READ COMMITTED.
 * Fixtures are committed for real via the actual ingest path, and {@code @BeforeEach} cleans up.
 */
@SpringBootTest
class SbomQualityFindingServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private SbomParser sbomParser;

    @Autowired
    private SBOMService sbomService;

    @Autowired
    private SbomQualityFindingService sbomQualityFindingService;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private SbomQualityFindingRepository findingRepository;

    private Product product;

    @BeforeEach
    void seed() {
        findingRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();

        Product p = new Product();
        p.setName("quality-finding-" + UUID.randomUUID());
        product = productRepository.saveAndFlush(p);
    }

    @Test
    void lowScoreCreatesOneActiveFinding() throws Exception {
        SBOM sbom = upload(product, poor(), null);

        sbomQualityFindingService.reconcileForSbom(sbom.getId());

        List<SbomQualityFinding> findings = findingRepository.findAll();
        assertThat(findings).hasSize(1);
        SbomQualityFinding finding = findings.get(0);
        assertThat(finding.getProductId()).isEqualTo(product.getId());
        assertThat(finding.getScopeSbomId()).isNull();
        assertThat(finding.getLifecycleStage()).isNull();
        assertThat(finding.getSbomId()).isEqualTo(sbom.getId());
        assertThat(finding.getQuality()).isNotNull();
        assertThat(finding.getQuality().getScore()).isLessThan(SbomQualityScorer.FINDING_THRESHOLD);
        assertThat(finding.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
    }

    @Test
    void runningTwiceIsIdempotentSameIdNoDuplicate() throws Exception {
        SBOM sbom = upload(product, poor(), null);

        sbomQualityFindingService.reconcileForSbom(sbom.getId());
        List<SbomQualityFinding> first = findingRepository.findAll();
        assertThat(first).hasSize(1);
        UUID id = first.get(0).getId();

        sbomQualityFindingService.reconcileForSbom(sbom.getId());
        List<SbomQualityFinding> second = findingRepository.findAll();
        assertThat(second).hasSize(1);
        assertThat(second.get(0).getId()).isEqualTo(id);
    }

    @Test
    void secondPoorUploadToSameSlotUpdatesTheSameRow() throws Exception {
        SBOM first = upload(product, poor(), null);
        sbomQualityFindingService.reconcileForSbom(first.getId());
        UUID findingId = findingRepository.findAll().get(0).getId();

        SBOM second = upload(product, poor(), null);
        sbomQualityFindingService.reconcileForSbom(second.getId());

        List<SbomQualityFinding> findings = findingRepository.findAll();
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).getId()).isEqualTo(findingId);
        assertThat(findings.get(0).getSbomId()).isEqualTo(second.getId());
    }

    @Test
    void improvedUploadToSameSlotAutoResolvesThenLaterPoorUploadRevivesSameRow() throws Exception {
        SBOM poorSbom = upload(product, poor(), null);
        sbomQualityFindingService.reconcileForSbom(poorSbom.getId());
        UUID findingId = findingRepository.findAll().get(0).getId();

        SBOM goodSbom = upload(product, complete(), null);
        sbomQualityFindingService.reconcileForSbom(goodSbom.getId());

        SbomQualityFinding afterGood = findingRepository.findById(findingId).orElseThrow();
        assertThat(afterGood.getLifecycleState()).isEqualTo(AlertLifecycleState.AUTO_RESOLVED);
        assertThat(afterGood.getSbomId()).isEqualTo(goodSbom.getId());

        SBOM poorAgain = upload(product, poor(), null);
        sbomQualityFindingService.reconcileForSbom(poorAgain.getId());

        SbomQualityFinding revived = findingRepository.findById(findingId).orElseThrow();
        assertThat(revived.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(revived.getSbomId()).isEqualTo(poorAgain.getId());
        assertThat(findingRepository.findAll()).hasSize(1);
    }

    @Test
    void unstagedPoorThenBuildCompleteAutoResolvesUnstagedFindingWithNoBuildFinding() throws Exception {
        SBOM unstaged = upload(product, poor(), null);
        sbomQualityFindingService.reconcileForSbom(unstaged.getId());
        assertThat(findingRepository.findAll()).hasSize(1);
        UUID unstagedFindingId = findingRepository.findAll().get(0).getId();

        SBOM build = upload(product, complete(), SbomLifecycleStage.BUILD);
        sbomQualityFindingService.reconcileForSbom(build.getId());

        SbomQualityFinding unstagedFinding = findingRepository.findById(unstagedFindingId).orElseThrow();
        assertThat(unstagedFinding.getLifecycleState()).isEqualTo(AlertLifecycleState.AUTO_RESOLVED);
        assertThat(findingRepository.findAll()).hasSize(1);
    }

    @Test
    void buildPoorAndDeployedPoorAreTwoIndependentFindings() throws Exception {
        SBOM build = upload(product, poor(), SbomLifecycleStage.BUILD);
        sbomQualityFindingService.reconcileForSbom(build.getId());

        SBOM deployed = upload(product, poor(), SbomLifecycleStage.DEPLOYED);
        sbomQualityFindingService.reconcileForSbom(deployed.getId());

        List<SbomQualityFinding> findings = findingRepository.findAll();
        assertThat(findings).hasSize(2);
        assertThat(findings).extracting(SbomQualityFinding::getLifecycleStage)
                .containsExactlyInAnyOrder(SbomLifecycleStage.BUILD, SbomLifecycleStage.DEPLOYED);
        assertThat(findings).allMatch(f -> f.getLifecycleState() == AlertLifecycleState.ACTIVE);
    }

    @Test
    void bucketProductWithTwoPoorUploadsGetsTwoFindingsEachWithItsOwnScopeSbomId() throws Exception {
        Product bucket = new Product();
        bucket.setName("bucket-" + UUID.randomUUID());
        bucket.setUnassigned(true);
        bucket = productRepository.saveAndFlush(bucket);

        SBOM b1 = upload(bucket, poor(), null);
        sbomQualityFindingService.reconcileForSbom(b1.getId());
        SBOM b2 = upload(bucket, poor(), null);
        sbomQualityFindingService.reconcileForSbom(b2.getId());

        List<SbomQualityFinding> findings = findingRepository.findAll();
        assertThat(findings).hasSize(2);
        assertThat(findings).extracting(SbomQualityFinding::getScopeSbomId)
                .containsExactlyInAnyOrder(b1.getId(), b2.getId());
    }

    @Test
    void inactiveSbomIsSkipped() throws Exception {
        // Note: the upload's own commit already fired the after-commit listener once (a real finding
        // was created for this poor SBOM while it was still active) — same as
        // QuantumFindingServiceTest's analogous test. This asserts only that the explicit call made
        // AFTER marking the SBOM inactive is itself a no-op, not that the finding table is empty.
        SBOM sbom = upload(product, poor(), null);
        SBOM fresh = sbomRepository.findById(sbom.getId()).orElseThrow();
        fresh.setActive(false);
        sbomRepository.saveAndFlush(fresh);

        var summary = sbomQualityFindingService.reconcileForSbom(sbom.getId());
        assertThat(summary).isEqualTo(SbomQualityFindingService.SbomQualityReconcileSummary.EMPTY);
    }

    @Test
    void standaloneCbomToASlotWithAnExistingFindingIsNotScoredAndAutoResolvesTheFinding() throws Exception {
        SBOM poorSbom = upload(product, poor(), null);
        sbomQualityFindingService.reconcileForSbom(poorSbom.getId());
        UUID findingId = findingRepository.findAll().get(0).getId();

        SBOM cbom = upload(product, standaloneCbom(), null);
        SBOM cbomFresh = sbomRepository.findById(cbom.getId()).orElseThrow();
        assertThat(cbomFresh.getQuality()).isNull();

        sbomQualityFindingService.reconcileForSbom(cbom.getId());

        SbomQualityFinding finding = findingRepository.findById(findingId).orElseThrow();
        assertThat(finding.getLifecycleState()).isEqualTo(AlertLifecycleState.AUTO_RESOLVED);
        assertThat(finding.getSbomId()).isEqualTo(cbom.getId());
    }

    /* ------------------------------------------------------------------ */

    private SBOM upload(Product targetProduct, String json, SbomLifecycleStage stage) throws Exception {
        NormalizedSbom document = sbomParser.parse(mapper.readTree(json));
        SBOM placeholder = sbomService.createPlaceholder(targetProduct, document, "1.0.0", json, null, null, null, stage);
        sbomService.ingestDocument(placeholder, document, JobProgress.NOOP);
        return sbomRepository.findById(placeholder.getId()).orElseThrow();
    }

    /** Three components, name+version, one PURL, no supplier/author/timestamp/dependencies. Scores 33. */
    private static String poor() {
        return """
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [
                    { "type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20" },
                    { "type": "library", "name": "left-pad", "version": "1.3.0" },
                    { "type": "library", "name": "is-odd", "version": "3.0.1" }
                  ] }
                """;
    }

    /** Every element present. Scores 100. */
    private static String complete() {
        return """
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": {
                    "timestamp": "2026-09-20T10:00:00Z",
                    "authors": [ { "name": "Acme Build Team" } ]
                  },
                  "components": [
                    { "type": "library", "bom-ref": "a", "name": "a", "version": "1.0.0",
                      "purl": "pkg:npm/a@1.0.0", "supplier": { "name": "Acme" } },
                    { "type": "library", "bom-ref": "b", "name": "b", "version": "1.0.0",
                      "purl": "pkg:npm/b@1.0.0", "supplier": { "name": "Acme" } }
                  ],
                  "dependencies": [
                    { "ref": "a", "dependsOn": [] },
                    { "ref": "b", "dependsOn": [] }
                  ] }
                """;
    }

    /** Every component is a cryptographic-asset — an empty scored population, quality stays null. */
    private static String standaloneCbom() {
        return """
                { "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                  "components": [
                    { "type": "cryptographic-asset", "bom-ref": "key-rsa", "name": "RSA-2048",
                      "cryptoProperties": { "assetType": "related-crypto-material",
                        "relatedCryptoMaterialProperties": { "type": "private-key", "size": 2048 } } }
                  ] }
                """;
    }

}
