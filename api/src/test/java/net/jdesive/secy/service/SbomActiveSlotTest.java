package net.jdesive.secy.service;

import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.component.SbomFormat;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The M1e active-SBOM slot invariant: {@code (product, lifecycleStage)}, not {@code product} alone.
 * The highest-risk regression this milestone can produce is a bad slot rule silently reviving the
 * pre-M1e "one active SBOM per product" bug (or its opposite, leaving stale slots active forever), so
 * every transition {@link SBOMService#createPlaceholder} can make is pinned here directly, without
 * going through the controller or the job queue.
 */
@SpringBootTest
@Transactional
class SbomActiveSlotTest {

    @Autowired
    private SBOMService sbomService;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    private Product product;

    @BeforeEach
    void seed() {
        Product p = new Product();
        p.setName("slot-test-" + UUID.randomUUID());
        product = productRepository.saveAndFlush(p);
    }

    /* ------------------------------------------------------------------ */
    /* Legacy (unstaged) mode                                             */
    /* ------------------------------------------------------------------ */

    @Test
    void unstagedThenUnstagedDeactivatesTheFirst() {
        SBOM first = upload(null);
        SBOM second = upload(null);

        assertActive(first, false);
        assertActive(second, true);
    }

    /* ------------------------------------------------------------------ */
    /* Staged mode                                                        */
    /* ------------------------------------------------------------------ */

    @Test
    void sourceThenBuildBothStaySctive() {
        SBOM source = upload(SbomLifecycleStage.SOURCE);
        SBOM build = upload(SbomLifecycleStage.BUILD);

        assertActive(source, true);
        assertActive(build, true);
    }

    @Test
    void buildThenBuildDeactivatesTheFirstSourceUntouched() {
        SBOM source = upload(SbomLifecycleStage.SOURCE);
        SBOM firstBuild = upload(SbomLifecycleStage.BUILD);
        SBOM secondBuild = upload(SbomLifecycleStage.BUILD);

        assertActive(source, true);
        assertActive(firstBuild, false);
        assertActive(secondBuild, true);
    }

    @Test
    void unstagedThenSourceDeactivatesTheUnstagedOne() {
        SBOM unstaged = upload(null);
        SBOM source = upload(SbomLifecycleStage.SOURCE);

        assertActive(unstaged, false);
        assertActive(source, true);
    }

    @Test
    void sourceAndBuildThenUnstagedDeactivatesBothPriorStages() {
        SBOM source = upload(SbomLifecycleStage.SOURCE);
        SBOM build = upload(SbomLifecycleStage.BUILD);
        SBOM unstaged = upload(null);

        assertActive(source, false);
        assertActive(build, false);
        assertActive(unstaged, true);
    }

    /**
     * Regression guard for the removed {@code Optional findByProductIdAndActiveTrue} query: two
     * pre-existing hand-built active unstaged SBOMs (as if written before this invariant existed, or
     * left behind by a race) must not blow up an unstaged upload — every one of them deactivates.
     */
    @Test
    void twoPreExistingActiveUnstagedSbomsBothDeactivateOnAnUnstagedUploadWithNoException() {
        SBOM handBuiltOne = handBuiltActiveSbom(null);
        SBOM handBuiltTwo = handBuiltActiveSbom(null);

        SBOM upload = upload(null);

        assertActive(handBuiltOne, false);
        assertActive(handBuiltTwo, false);
        assertActive(upload, true);
    }

    /* ------------------------------------------------------------------ */
    /* The Unassigned bucket (M1a) — unchanged by M1e                     */
    /* ------------------------------------------------------------------ */

    @Test
    void theBucketKeepsEveryStagedAndUnstagedSbomActive() {
        Product bucket = new Product();
        bucket.setName("slot-test-bucket-" + UUID.randomUUID());
        bucket.setUnassigned(true);
        bucket = productRepository.saveAndFlush(bucket);

        SBOM unstaged = uploadFor(bucket, null);
        SBOM source = uploadFor(bucket, SbomLifecycleStage.SOURCE);
        SBOM anotherSource = uploadFor(bucket, SbomLifecycleStage.SOURCE);

        assertActive(unstaged, true);
        assertActive(source, true);
        assertActive(anotherSource, true);
    }

    /* ------------------------------------------------------------------ */
    /* Stage resolution                                                   */
    /* ------------------------------------------------------------------ */

    @Test
    void explicitStageBeatsAConflictingDocumentStage() {
        NormalizedSbom document = document(SbomLifecycleStage.SOURCE);
        SBOM sbom = sbomService.createPlaceholder(product, document, "1.0", null, null, null, null,
                SbomLifecycleStage.BUILD);
        assertThat(reload(sbom).getLifecycleStage()).isEqualTo(SbomLifecycleStage.BUILD);
    }

    @Test
    void documentStageIsUsedWhenExplicitStageIsNull() {
        NormalizedSbom document = document(SbomLifecycleStage.ANALYZED);
        SBOM sbom = sbomService.createPlaceholder(product, document, "1.0", null, null, null, null, null);
        assertThat(reload(sbom).getLifecycleStage()).isEqualTo(SbomLifecycleStage.ANALYZED);
    }

    @Test
    void fiveAndSevenArgOverloadsWithAStagelessDocumentGiveNullStage() {
        NormalizedSbom document = document(null);

        SBOM viaFiveArg = sbomService.createPlaceholder(product, document, "1.0", null, null);
        assertThat(reload(viaFiveArg).getLifecycleStage()).isNull();

        SBOM viaSevenArg = sbomService.createPlaceholder(product, document, "1.0", null, null, null, null);
        assertThat(reload(viaSevenArg).getLifecycleStage()).isNull();
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private SBOM upload(SbomLifecycleStage stage) {
        return uploadFor(product, stage);
    }

    private SBOM uploadFor(Product target, SbomLifecycleStage stage) {
        NormalizedSbom document = document(null);
        return sbomService.createPlaceholder(target, document, "1.0", null, null, null, null, stage);
    }

    private static NormalizedSbom document(SbomLifecycleStage declared) {
        return NormalizedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .specVersion("1.5")
                .version(1)
                .declaredLifecycleStage(declared)
                .build();
    }

    private SBOM handBuiltActiveSbom(SbomLifecycleStage stage) {
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.5");
        sbom.setVersion(1);
        sbom.setProductVersion("1.0");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        sbom.setUploadDate(LocalDateTime.now());
        sbom.setLifecycleStage(stage);
        return sbomRepository.saveAndFlush(sbom);
    }

    private SBOM reload(SBOM sbom) {
        return sbomRepository.findById(sbom.getId()).orElseThrow();
    }

    private void assertActive(SBOM sbom, boolean expected) {
        assertThat(reload(sbom).isActive()).as("SBOM %s active", sbom.getId()).isEqualTo(expected);
    }

}
