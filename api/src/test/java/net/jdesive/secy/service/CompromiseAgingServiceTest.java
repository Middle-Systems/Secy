package net.jdesive.secy.service;

import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IOC aging: the nightly sweep that stops stale evidence from holding the top of the primary screen
 * forever.
 *
 * <p>Drives {@link CompromiseAgingService#ageFindings()} directly rather than waiting on
 * {@code JobScheduler}'s cron — the same discipline the ingestion-queue tests follow with
 * {@code JobRunner}, and necessary here because the test profile disables every {@code @Scheduled}
 * (a nightly demotion firing mid-run would rewrite another test class's fixtures).
 *
 * <p>The window under test is the test profile's {@code secy.compromise.ioc-stale-after=P90D}.
 */
@SpringBootTest
class CompromiseAgingServiceTest {

    @Autowired
    private CompromiseAgingService agingService;

    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    /** Cleared for FK ordering, never seeded here — see {@code CompromiseDetectionServiceTest.reset}. */
    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    private SBOMComponent component;

    @BeforeEach
    void seed() {
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();

        Product product = new Product();
        product.setName("Aging Test Product");
        productRepository.saveAndFlush(product);

        SBOMComponent pkg = new SBOMComponent();
        pkg.setName("bad-pkg");
        pkg.setVersion("1.0.0");
        pkg.setPurl("pkg:npm/bad-pkg@1.0.0");

        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        pkg.setSbom(sbom);
        sbom.getComponents().add(pkg);
        component = sbomRepository.saveAndFlush(sbom).getComponents().get(0);
    }

    /* ---------------------------------------------------------------------- */
    /* The transition                                                         */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void anIocOlderThanTheWindowDemotesConfirmedToInvestigateWithoutDeletingAnything() {
        UUID staleId = finding(f -> {
            f.setConfidence(CompromiseConfidence.CONFIRMED);
            f.setIocFirstSeen(LocalDateTime.now().minusDays(200));
            f.setIocLastSeen(LocalDateTime.now().minusDays(120));
        });

        assertThat(agingService.ageFindings()).isEqualTo(1);

        CompromiseFinding aged = findingRepository.findById(staleId).orElseThrow();
        assertThat(aged.getConfidence()).isEqualTo(CompromiseConfidence.INVESTIGATE);
        assertThat(aged.getAgedAt())
                .as("a non-null agedAt is how the UI explains the demotion")
                .isNotNull();
        assertThat(aged.getLifecycleState())
                .as("demoted, never deleted, and never auto-resolved — that is the scanner's verdict, "
                        + "not aging's")
                .isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(findingRepository.count()).isEqualTo(1);
    }

    @Test
    @Transactional
    void aLikelyFindingDemotesTooAndAFreshOneIsLeftAlone() {
        UUID stale = finding(f -> {
            f.setConfidence(CompromiseConfidence.LIKELY);
            f.setIocLastSeen(LocalDateTime.now().minusDays(400));
        });
        UUID fresh = finding(f -> {
            f.setConfidence(CompromiseConfidence.CONFIRMED);
            f.setIocId("MAL-FRESH");
            f.setIocLastSeen(LocalDateTime.now().minusDays(2));
        });
        // Exactly on the boundary: 90 days is not yet PAST the 90-day window.
        UUID onBoundary = finding(f -> {
            f.setConfidence(CompromiseConfidence.CONFIRMED);
            f.setIocId("MAL-BOUNDARY");
            f.setIocLastSeen(LocalDateTime.now().minusDays(90).plusMinutes(1));
        });

        assertThat(agingService.ageFindings()).isEqualTo(1);

        assertThat(findingRepository.findById(stale).orElseThrow().getConfidence())
                .isEqualTo(CompromiseConfidence.INVESTIGATE);
        assertThat(findingRepository.findById(fresh).orElseThrow().getConfidence())
                .isEqualTo(CompromiseConfidence.CONFIRMED);
        assertThat(findingRepository.findById(onBoundary).orElseThrow().getConfidence())
                .as("the comparison is strictly-before, so a finding on the boundary survives")
                .isEqualTo(CompromiseConfidence.CONFIRMED);
    }

    @Test
    @Transactional
    void agingIsIdempotentAndSkipsWhatItHasAlreadyDemoted() {
        finding(f -> {
            f.setConfidence(CompromiseConfidence.CONFIRMED);
            f.setIocLastSeen(LocalDateTime.now().minusDays(120));
        });

        assertThat(agingService.ageFindings()).isEqualTo(1);
        assertThat(agingService.ageFindings())
                .as("already at the floor — the query only selects CONFIRMED/LIKELY")
                .isZero();
    }

    @Test
    @Transactional
    void anAutoResolvedFindingIsNotTouched() {
        // It is already off both screens; demoting it would be busywork on a row nobody is looking at.
        UUID resolved = finding(f -> {
            f.setConfidence(CompromiseConfidence.CONFIRMED);
            f.setIocLastSeen(LocalDateTime.now().minusDays(400));
            f.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
        });

        assertThat(agingService.ageFindings()).isZero();
        assertThat(findingRepository.findById(resolved).orElseThrow().getConfidence())
                .isEqualTo(CompromiseConfidence.CONFIRMED);
    }

    @Test
    @Transactional
    void aFindingWithNoIocTimestampsAtAllAgesFromWhenSecyFirstLearnedOfIt() {
        // The freshnessReference fallback: iocLastSeen -> iocFirstSeen -> createdAt. A feed row that
        // stated no timestamps must still age, rather than being exempt forever.
        UUID noTimestamps = finding(f -> {
            f.setConfidence(CompromiseConfidence.CONFIRMED);
            f.setIocFirstSeen(null);
            f.setIocLastSeen(null);
            f.setCreatedAt(LocalDateTime.now().minusDays(365));
        });

        assertThat(agingService.ageFindings()).isEqualTo(1);
        assertThat(findingRepository.findById(noTimestamps).orElseThrow().getConfidence())
                .isEqualTo(CompromiseConfidence.INVESTIGATE);
    }

    /* ---------------------------------------------------------------------- */
    /* The off switches                                                       */
    /* ---------------------------------------------------------------------- */

    /** {@code aging-enabled=false} is the documented way to get the pre-Phase-6 behaviour back. */
    @SpringBootTest
    @TestPropertySource(properties = "secy.compromise.aging-enabled=false")
    static class Disabled extends AgingOffFixture {
    }

    /**
     * A zero window disables aging rather than demoting everything instantly — an operator who
     * typoed a duration should get the old behaviour, not a dashboard where every finding has
     * silently dropped to INVESTIGATE.
     */
    @SpringBootTest
    @TestPropertySource(properties = "secy.compromise.ioc-stale-after=PT0S")
    static class ZeroWindow extends AgingOffFixture {
    }

    /** Shared body for the two "aging must do nothing" configurations. */
    abstract static class AgingOffFixture {

        @Autowired
        private CompromiseAgingService agingService;

        @Autowired
        private CompromiseFindingRepository findingRepository;

        @Autowired
        private SBOMRepository sbomRepository;

        @Autowired
        private ProductRepository productRepository;

        @Autowired
        private VulnerabilityAlertRepository alertRepository;

        @Test
        @Transactional
        void nothingIsDemoted() {
            findingRepository.deleteAll();
            alertRepository.deleteAll();
            sbomRepository.deleteAll();
            productRepository.deleteAll();

            Product product = new Product();
            product.setName("Aging Off Product");
            productRepository.saveAndFlush(product);

            SBOMComponent pkg = new SBOMComponent();
            pkg.setName("bad-pkg");
            pkg.setVersion("1.0.0");
            pkg.setPurl("pkg:npm/bad-pkg@1.0.0");
            SBOM sbom = new SBOM();
            sbom.setProduct(product);
            sbom.setActive(true);
            pkg.setSbom(sbom);
            sbom.getComponents().add(pkg);
            SBOMComponent saved = sbomRepository.saveAndFlush(sbom).getComponents().get(0);

            CompromiseFinding ancient = new CompromiseFinding();
            ancient.setComponent(saved);
            ancient.setType(CompromiseType.MALICIOUS_PACKAGE);
            ancient.setConfidence(CompromiseConfidence.CONFIRMED);
            ancient.setSource("OpenSSF Malicious Packages");
            ancient.setIocId("MAL-2019-0001");
            ancient.setMatchedOn("pkg:npm/bad-pkg@1.0.0");
            ancient.setLifecycleState(AlertLifecycleState.ACTIVE);
            ancient.setIocLastSeen(LocalDateTime.now().minusDays(2000));
            UUID id = findingRepository.saveAndFlush(ancient).getId();

            assertThat(agingService.ageFindings()).isZero();
            assertThat(findingRepository.findById(id).orElseThrow().getConfidence())
                    .isEqualTo(CompromiseConfidence.CONFIRMED);
        }
    }

    /* ---------------------------------------------------------------------- */
    /* Fixtures                                                               */
    /* ---------------------------------------------------------------------- */

    private UUID finding(Consumer<CompromiseFinding> customise) {
        CompromiseFinding finding = new CompromiseFinding();
        finding.setComponent(component);
        finding.setType(CompromiseType.MALICIOUS_PACKAGE);
        finding.setSource("OpenSSF Malicious Packages");
        finding.setIocId("MAL-2026-0001");
        finding.setMatchedOn("pkg:npm/bad-pkg@1.0.0");
        finding.setSummary("Malicious code in bad-pkg (npm)");
        finding.setLifecycleState(AlertLifecycleState.ACTIVE);
        finding.setLastSeenAt(LocalDateTime.now());
        customise.accept(finding);
        return findingRepository.saveAndFlush(finding).getId();
    }

}
