package net.jdesive.secy.service.lifecycle;

import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
import net.jdesive.secy.persistence.entity.LifecycleDriftKind;
import net.jdesive.secy.persistence.entity.LifecycleStagePair;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.service.lifecycle.LifecycleDiffService.LifecycleDiffRunSummary;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link LifecycleDiffService#runForSbom}, called directly (the listener does not fire in a
 * {@code @Transactional} test — see {@code LifecycleDiffListenerTest} and
 * {@code LifecycleDriftAcceptanceTest} for the real end-to-end path). Hand-builds SBOMs with
 * {@code status="COMPLETED"} — confirmed against {@code VulnerabilityScanner}, which is the only
 * writer of that exact string.
 *
 * <p><b>Deliberately not {@code @Transactional}.</b> {@link LifecycleDiffService#runForSbom} is
 * {@code REQUIRES_NEW} — inside a {@code @Transactional} test method, that would suspend the test's
 * own (uncommitted) transaction and run the diff in a genuinely separate transaction that, under
 * ordinary read-committed semantics, cannot see the hand-built fixtures this test just "saved" but
 * never committed. Fixtures are committed for real here instead, and cleaned up per test the same way
 * {@code SbomUploadJobFlowTest} does.
 */
@SpringBootTest
class LifecycleDiffServiceTest {

    @Autowired
    private LifecycleDiffService lifecycleDiffService;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private LifecycleDriftFindingRepository findingRepository;

    private Product product;

    @BeforeEach
    void seed() {
        findingRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();

        Product p = new Product();
        p.setName("diff-service-" + UUID.randomUUID());
        product = productRepository.saveAndFlush(p);
    }

    @Test
    void aBuildSbomWithAllThreeCounterpartsRunsThreePairs() {
        sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"));
        sbom(SbomLifecycleStage.ANALYZED, "COMPLETED", npm("a", "1.0.0"));
        sbom(SbomLifecycleStage.DEPLOYED, "COMPLETED", npm("a", "1.0.0"));
        SBOM build = sbom(SbomLifecycleStage.BUILD, "COMPLETED", npm("a", "1.0.0"));

        LifecycleDiffRunSummary summary = lifecycleDiffService.runForSbom(build.getId());

        assertThat(summary.pairsEvaluated()).isEqualTo(3);
    }

    @Test
    void aSourceRunWithOnlyDeployedPresentRunsZeroPairs() {
        sbom(SbomLifecycleStage.DEPLOYED, "COMPLETED", npm("a", "1.0.0"));
        SBOM source = sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"));

        LifecycleDiffRunSummary summary = lifecycleDiffService.runForSbom(source.getId());

        assertThat(summary.pairsEvaluated()).isZero();
    }

    @Test
    void anAnalyzedRunRunsOnlyBuildAnalyzed() {
        sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"));
        sbom(SbomLifecycleStage.BUILD, "COMPLETED", npm("a", "1.0.0"));
        SBOM analyzed = sbom(SbomLifecycleStage.ANALYZED, "COMPLETED", npm("a", "1.0.0"));

        LifecycleDiffRunSummary summary = lifecycleDiffService.runForSbom(analyzed.getId());

        assertThat(summary.pairsEvaluated()).isEqualTo(1);
    }

    @Test
    void counterpartQueuedOrFailedSkipsThePairAndLeavesPriorFindingsUntouched() {
        SBOM source = sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"), npm("b", "1.0.0"));
        SBOM build = sbom(SbomLifecycleStage.BUILD, "COMPLETED", npm("a", "1.0.0"), npm("injected", "1.0.0"));
        lifecycleDiffService.runForSbom(build.getId());
        assertThat(findingRepository.findAll()).hasSize(1);

        // A new Build supersedes the old one but is still QUEUED (no components ingested yet in this
        // hand-built scenario) — the pair must be skipped, not diffed against an empty component set.
        SBOM queuedBuild = sbom(SbomLifecycleStage.BUILD, "QUEUED");
        deactivate(build);

        LifecycleDiffRunSummary summary = lifecycleDiffService.runForSbom(source.getId());
        assertThat(summary.pairsEvaluated()).isZero();
        assertThat(findingRepository.findAll()).hasSize(1);
        assertThat(findingRepository.findAll().get(0).getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
    }

    @Test
    void inactiveUnstagedProductlessOrBucketSbomGivesAnEmptySummary() {
        SBOM inactive = sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"));
        deactivate(inactive);
        assertThat(lifecycleDiffService.runForSbom(inactive.getId()).pairsEvaluated()).isZero();

        SBOM unstaged = sbom(null, "COMPLETED", npm("a", "1.0.0"));
        assertThat(lifecycleDiffService.runForSbom(unstaged.getId()).pairsEvaluated()).isZero();

        SBOM noProduct = new SBOM();
        noProduct.setFormat("CycloneDX");
        noProduct.setSpecVersion("1.5");
        noProduct.setVersion(1);
        noProduct.setActive(true);
        noProduct.setStatus("COMPLETED");
        noProduct.setUploadDate(LocalDateTime.now());
        noProduct.setLifecycleStage(SbomLifecycleStage.SOURCE);
        noProduct = sbomRepository.saveAndFlush(noProduct);
        assertThat(lifecycleDiffService.runForSbom(noProduct.getId()).pairsEvaluated()).isZero();

        Product bucket = new Product();
        bucket.setName("bucket-" + UUID.randomUUID());
        bucket.setUnassigned(true);
        bucket = productRepository.saveAndFlush(bucket);
        SBOM bucketSbom = sbomFor(bucket, SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"));
        assertThat(lifecycleDiffService.runForSbom(bucketSbom.getId()).pairsEvaluated()).isZero();

        assertThat(lifecycleDiffService.runForSbom(UUID.randomUUID()).pairsEvaluated())
                .as("nonexistent SBOM")
                .isZero();
    }

    @Test
    void rootComponentIsExcludedIdenticalComponentsDifferentRootsProduceNoFindings() {
        SBOM source = sbomWithRoot(SbomLifecycleStage.SOURCE, "acme-web", npm("a", "1.0.0"));
        SBOM build = sbomWithRoot(SbomLifecycleStage.BUILD, "acme-web-build", npm("a", "1.0.0"));

        lifecycleDiffService.runForSbom(build.getId());

        assertThat(findingRepository.findAll()).isEmpty();
    }

    @Test
    void runningTwiceIsIdempotentSameIdsAndCountsNoDuplicates() {
        sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"));
        SBOM build = sbom(SbomLifecycleStage.BUILD, "COMPLETED", npm("a", "1.0.0"), npm("injected", "1.0.0"));

        lifecycleDiffService.runForSbom(build.getId());
        List<LifecycleDriftFinding> first = findingRepository.findAll();
        assertThat(first).hasSize(1);
        UUID id = first.get(0).getId();

        lifecycleDiffService.runForSbom(build.getId());
        List<LifecycleDriftFinding> second = findingRepository.findAll();
        assertThat(second).hasSize(1);
        assertThat(second.get(0).getId()).isEqualTo(id);
    }

    @Test
    void kindFlipFromUnexpectedToVersionMismatchAutoResolvesOldRowAndCreatesNew() {
        SBOM oldSource = sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"));
        SBOM oldBuild = sbom(SbomLifecycleStage.BUILD, "COMPLETED", npm("a", "1.0.0"), npm("shifted", "1.0.0"));
        lifecycleDiffService.runForSbom(oldBuild.getId());

        List<LifecycleDriftFinding> afterFirst = findingRepository.findAll();
        assertThat(afterFirst).hasSize(1);
        assertThat(afterFirst.get(0).getDriftKind()).isEqualTo(LifecycleDriftKind.UNEXPECTED_COMPONENT);
        UUID oldId = afterFirst.get(0).getId();

        // Supersede both slots: the new Source now declares "shifted" too, but at a different
        // (also concrete) version than what the new Build ships — UNEXPECTED_COMPONENT flips to
        // VERSION_MISMATCH for the same identity.
        deactivate(oldSource);
        deactivate(oldBuild);
        sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"), npm("shifted", "2.0.0"));
        SBOM newBuild = sbom(SbomLifecycleStage.BUILD, "COMPLETED", npm("a", "1.0.0"), npm("shifted", "1.0.0"));

        lifecycleDiffService.runForSbom(newBuild.getId());

        List<LifecycleDriftFinding> afterSecond = findingRepository.findAll();
        LifecycleDriftFinding oldRow = afterSecond.stream().filter(f -> f.getId().equals(oldId)).findFirst().orElseThrow();
        assertThat(oldRow.getLifecycleState()).isEqualTo(AlertLifecycleState.AUTO_RESOLVED);

        List<LifecycleDriftFinding> active = afterSecond.stream()
                .filter(f -> f.getLifecycleState() == AlertLifecycleState.ACTIVE).toList();
        assertThat(active).hasSize(1);
        assertThat(active.get(0).getDriftKind()).isEqualTo(LifecycleDriftKind.VERSION_MISMATCH);
        assertThat(active.get(0).getIdentityKey()).isEqualTo("npm/shifted");
    }

    @Test
    void removedRaisesNothingButCountsInRemovedIgnored() {
        sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"), npm("b", "1.0.0"));
        SBOM build = sbom(SbomLifecycleStage.BUILD, "COMPLETED", npm("a", "1.0.0"));

        LifecycleDiffRunSummary summary = lifecycleDiffService.runForSbom(build.getId());

        assertThat(findingRepository.findAll()).isEmpty();
        assertThat(summary.removedIgnored()).isEqualTo(1);
    }

    @Test
    void tenantIdIsCopiedFromTheSbom() {
        sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"));
        SBOM build = sbom(SbomLifecycleStage.BUILD, "COMPLETED", npm("a", "1.0.0"), npm("injected", "1.0.0"));

        lifecycleDiffService.runForSbom(build.getId());

        LifecycleDriftFinding finding = findingRepository.findAll().get(0);
        assertThat(finding.getTenantId()).isEqualTo(build.getTenantId());
    }

    @Test
    void summaryTextContainsThePairWording() {
        sbom(SbomLifecycleStage.SOURCE, "COMPLETED", npm("a", "1.0.0"));
        SBOM build = sbom(SbomLifecycleStage.BUILD, "COMPLETED", npm("a", "1.0.0"), npm("injected", "1.0.0"));

        lifecycleDiffService.runForSbom(build.getId());

        LifecycleDriftFinding finding = findingRepository.findAll().get(0);
        assertThat(finding.getSummary())
                .contains("injected")
                .contains("Build SBOM")
                .contains("Source SBOM")
                .contains("dependency confusion or build-time injection");
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Reloads {@code sbom} fresh before flipping it inactive and saving — a detached entity handed
     * back from an earlier, now-committed {@code saveAndFlush} cannot be safely re-saved directly
     * (its uninitialized {@code orphanRemoval} collections trip Hibernate's "no longer referenced by
     * the owning entity instance" check across sessions).
     */
    private void deactivate(SBOM sbom) {
        SBOM fresh = sbomRepository.findById(sbom.getId()).orElseThrow();
        fresh.setActive(false);
        sbomRepository.saveAndFlush(fresh);
    }

    private static SBOMComponent npm(String name, String version) {
        SBOMComponent component = new SBOMComponent();
        component.setName(name);
        component.setVersion(version);
        component.setPurl("pkg:npm/" + name + "@" + version);
        component.setType("library");
        return component;
    }

    private SBOM sbom(SbomLifecycleStage stage, String status, SBOMComponent... components) {
        return sbomFor(product, stage, status, components);
    }

    private SBOM sbomFor(Product target, SbomLifecycleStage stage, String status, SBOMComponent... components) {
        SBOM sbom = new SBOM();
        sbom.setProduct(target);
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.5");
        sbom.setVersion(1);
        sbom.setProductVersion("1.0.0");
        sbom.setActive(true);
        sbom.setStatus(status);
        sbom.setUploadDate(LocalDateTime.now());
        sbom.setLifecycleStage(stage);
        for (SBOMComponent component : components) {
            component.setSbom(sbom);
            sbom.getComponents().add(component);
        }
        return sbomRepository.saveAndFlush(sbom);
    }

    private SBOM sbomWithRoot(SbomLifecycleStage stage, String rootName, SBOMComponent... components) {
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

        SBOMComponent root = new SBOMComponent();
        root.setName(rootName);
        root.setVersion("1.0.0");
        root.setType("application");
        root.setSbom(sbom);
        sbom.setComponent(root);
        sbom.getComponents().add(root);

        for (SBOMComponent component : components) {
            component.setSbom(sbom);
            sbom.getComponents().add(component);
        }
        return sbomRepository.saveAndFlush(sbom);
    }

}
