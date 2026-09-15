package net.jdesive.secy.correlation;

import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.MaliciousPackageRepository;
import net.jdesive.secy.persistence.MalwareHashRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.ComponentHash;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.MaliciousPackage;
import net.jdesive.secy.persistence.entity.MaliciousPackageRange;
import net.jdesive.secy.persistence.entity.MalwareHash;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
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
 * Compromise detection itself: which components get findings, at what confidence, and what a
 * re-scan does to them.
 *
 * <p>Pins the confidence ladder documented on {@code CompromiseDetectionService.evaluate} —
 * {@code CONFIRMED} when the feed's statement covers the artefact with no inference,
 * {@code LIKELY} when reaching it needed one. Getting that boundary wrong in either direction is
 * the whole risk of this phase: too loose and every clean version of a once-hijacked package
 * screams CRITICAL, too tight and malware ships silently.
 */
@SpringBootTest
class CompromiseDetectionServiceTest {

    @Autowired
    private CompromiseDetectionService detectionService;

    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private MaliciousPackageRepository maliciousPackageRepository;

    @Autowired
    private MalwareHashRepository malwareHashRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private AssetRepository assetRepository;

    /** See {@link #reset()} — cleared for FK ordering, never seeded here. */
    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @BeforeEach
    @Transactional
    void reset() {
        // The H2 database is shared by every @SpringBootTest context in the run, so cleanup has to
        // be ordered by FK and complete.
        //
        // alertRepository is cleared even though this class never creates an alert: deleting an SBOM
        // cascades to its components, and a vulnerability_alert another test class left behind
        // citing one of those components would be deleted out from under that class's managed
        // Vulnerability.alerts collection (cascade=all-delete-orphan) — which surfaces much later as
        // "a collection with cascade=all-delete-orphan was no longer referenced by the owning entity
        // instance", in a completely unrelated test.
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        maliciousPackageRepository.deleteAll();
        malwareHashRepository.deleteAll();
    }

    /* ---------------------------------------------------------------------- */
    /* Malicious packages                                                     */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void aComponentWhosePurlMatchesASeededMaliciousPackageRaisesAConfirmedFinding() {
        seedWholePackage("MAL-2026-4502", "npm", "bucket-protocol-sdk-v2");

        SBOM sbom = sbomWith(component("bucket-protocol-sdk-v2", "1.0.26",
                "pkg:npm/bucket-protocol-sdk-v2@1.0.26"));

        CompromiseDetectionService.DetectionSummary summary = detectionService.detect(sbom);

        assertThat(summary.created()).isEqualTo(1);
        assertThat(summary.foundAnything()).isTrue();

        CompromiseFinding finding = onlyFinding();
        assertThat(finding.getType()).isEqualTo(CompromiseType.MALICIOUS_PACKAGE);
        assertThat(finding.getConfidence())
                .as("an unbounded introduced:\"0\" range covers every version with no arithmetic")
                .isEqualTo(CompromiseConfidence.CONFIRMED);
        assertThat(finding.getSeverity())
                .as("fixed at CRITICAL for every finding — not configurable in Phase 6")
                .isEqualTo("CRITICAL");
        assertThat(finding.getIocId()).isEqualTo("MAL-2026-4502");
        assertThat(finding.getMatchedOn())
                .as("what of YOURS matched, as the operator would recognise it")
                .isEqualTo("pkg:npm/bucket-protocol-sdk-v2@1.0.26");
        assertThat(finding.getSource()).isEqualTo("OpenSSF Malicious Packages");
        assertThat(finding.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(finding.getComponent()).isNotNull();
        assertThat(finding.getAssetComponent())
                .as("the Phase 4 XOR: exactly one component reference")
                .isNull();
        assertThat(finding.getIocLastSeen()).isNotNull();
    }

    @Test
    @Transactional
    void anEnumeratedVersionHitIsConfirmedAndAVersionOutsideTheListIsNotAFindingAtAll() {
        // The dangerous case: a package whose 1.0.1 was hijacked but whose 1.0.0 is clean. The
        // record still carries an introduced:"0" range (the feed's way of saying "we cannot express
        // the enumeration as an interval"), so a naive reading would condemn both.
        MaliciousPackage hijacked = seedWholePackage("MAL-2026-1", "npm", "partially-hijacked");
        hijacked.getVersions().add("1.0.1");
        maliciousPackageRepository.save(hijacked);

        SBOM bad = sbomWith(component("partially-hijacked", "1.0.1",
                "pkg:npm/partially-hijacked@1.0.1"));
        detectionService.detect(bad);
        assertThat(onlyFinding().getConfidence()).isEqualTo(CompromiseConfidence.CONFIRMED);

        findingRepository.deleteAll();

        SBOM clean = sbomWith(component("partially-hijacked", "1.0.0",
                "pkg:npm/partially-hijacked@1.0.0"));
        detectionService.detect(clean);
        assertThat(findingRepository.findAll())
                .as("a record that enumerates 1.0.1 does not implicate 1.0.0")
                .isEmpty();
    }

    @Test
    @Transactional
    void aBoundedRangeHitIsOnlyLikelyBecauseItRequiredIntervalArithmetic() {
        MaliciousPackage bounded = new MaliciousPackage();
        bounded.setMalId("MAL-2024-0001");
        bounded.setEcosystem("npm");
        bounded.setPackageName("bounded-pkg");
        bounded.setSummary("Malicious code in bounded-pkg (npm)");
        bounded.setIocLastSeen(LocalDateTime.now().minusDays(1));
        MaliciousPackageRange range = new MaliciousPackageRange();
        range.setRangeType("SEMVER");
        range.setIntroduced("2.0.0");
        range.setFixed("2.0.4");
        range.setMaliciousPackage(bounded);
        bounded.getRanges().add(range);
        maliciousPackageRepository.save(bounded);

        detectionService.detect(sbomWith(component("bounded-pkg", "2.0.2", "pkg:npm/bounded-pkg@2.0.2")));

        assertThat(onlyFinding().getConfidence())
                .as("the version fell inside a stated interval; the feed never named this build")
                .isEqualTo(CompromiseConfidence.LIKELY);
    }

    @Test
    @Transactional
    void aVersionOutsideABoundedRangeRaisesNothing() {
        MaliciousPackage bounded = new MaliciousPackage();
        bounded.setMalId("MAL-2024-0002");
        bounded.setEcosystem("npm");
        bounded.setPackageName("outside-pkg");
        MaliciousPackageRange range = new MaliciousPackageRange();
        range.setRangeType("SEMVER");
        range.setIntroduced("2.0.0");
        range.setFixed("2.0.4");
        range.setMaliciousPackage(bounded);
        bounded.getRanges().add(range);
        maliciousPackageRepository.save(bounded);

        detectionService.detect(sbomWith(component("outside-pkg", "2.0.9", "pkg:npm/outside-pkg@2.0.9")));

        assertThat(findingRepository.findAll()).isEmpty();
    }

    @Test
    @Transactional
    void aWithdrawnRecordRaisesNothingButIsNotDeleted() {
        MaliciousPackage withdrawn = seedWholePackage("MAL-2022-0009", "npm", "withdrawn-pkg");
        withdrawn.setWithdrawn(LocalDateTime.now().minusDays(5));
        maliciousPackageRepository.save(withdrawn);

        detectionService.detect(sbomWith(component("withdrawn-pkg", "1.0.0",
                "pkg:npm/withdrawn-pkg@1.0.0")));

        assertThat(findingRepository.findAll()).isEmpty();
        assertThat(maliciousPackageRepository.findByMalId("MAL-2022-0009"))
                .as("the record stays so a reversal needs no re-import")
                .hasSize(1);
    }

    @Test
    @Transactional
    void anOsPackageWithNoPurlIsOutOfScopeForThisFeedRatherThanNameMatched() {
        // No CPE-style fallback here on purpose: the corpus is keyed on (ecosystem, package) and
        // guessing would manufacture CRITICAL findings out of a name collision.
        seedWholePackage("MAL-2026-2", "npm", "openssl");

        SBOMComponent osPackage = component("openssl", "1.1.1", null);
        detectionService.detect(sbomWith(osPackage));

        assertThat(findingRepository.findAll()).isEmpty();
    }

    /* ---------------------------------------------------------------------- */
    /* Malware hashes                                                         */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void aComponentDigestMatchingASeededMalwareHashRaisesAConfirmedFinding() {
        String digest = "c24ccb6dd7f0b36890b5293f67ffc4756c01925db1532b5aca55fc0a2d0dc963";
        seedMalwareHash(digest, "Mirai", 1.0d);

        SBOMComponent component = component("innocuous-lib", "1.2.3", "pkg:npm/innocuous-lib@1.2.3");
        // CycloneDX spells it SHA-256; SPDX spells it SHA256. Both normalise to the same stored form.
        component.getHashes().add(ComponentHash.of("SHA-256", digest.toUpperCase(java.util.Locale.ROOT)));
        component.getHashes().add(ComponentHash.of("MD5", "c0c7a5906bcd128b5db7f04ca82a54c1"));

        detectionService.detect(sbomWith(component));

        CompromiseFinding finding = onlyFinding();
        assertThat(finding.getType()).isEqualTo(CompromiseType.MALWARE_HASH);
        assertThat(finding.getConfidence())
                .as("a digest equality is the strongest statement Secy can make about anything")
                .isEqualTo(CompromiseConfidence.CONFIRMED);
        assertThat(finding.getIocId()).isEqualTo(digest);
        assertThat(finding.getMatchedOn()).isEqualTo(digest);
        assertThat(finding.getSource()).isEqualTo("abuse.ch MalwareBazaar");
        assertThat(finding.getSummary()).contains("Mirai");
        assertThat(finding.getIocConfidence()).isEqualTo(1.0d);
    }

    @Test
    @Transactional
    void anAssetComponentDigestMatchesIdenticallyToAnSbomOne() {
        // The matcher must not be able to tell the two component kinds apart. Seeded directly
        // because no scanner normaliser populates asset digests yet — see AssetComponent.hashes.
        String digest = "3860906a1321b9873181998515682204e2145c7ca55de9abb0486d37a799c18a";
        seedMalwareHash(digest, "Js.Dropper", 0.9d);

        Asset asset = new Asset();
        asset.setType(AssetType.CONTAINER_IMAGE);
        asset.setName("acme/api:1.4.2");
        AssetComponent component = new AssetComponent();
        component.setAsset(asset);
        component.setName("dropper-lib");
        component.setVersion("0.1.0");
        component.setPurl("pkg:npm/dropper-lib@0.1.0");
        component.setSource(AssetComponentSource.TRIVY);
        component.setPresentInLastScan(true);
        component.getHashes().add(ComponentHash.of("SHA256", digest));
        asset.getComponents().add(component);
        Asset saved = assetRepository.saveAndFlush(asset);

        detectionService.detect(saved);

        CompromiseFinding finding = onlyFinding();
        assertThat(finding.getType()).isEqualTo(CompromiseType.MALWARE_HASH);
        assertThat(finding.getConfidence()).isEqualTo(CompromiseConfidence.CONFIRMED);
        assertThat(finding.getAssetComponent()).isNotNull();
        assertThat(finding.getComponent())
                .as("the Phase 4 XOR, from the asset side")
                .isNull();
    }

    @Test
    @Transactional
    void aNonSha256DigestIsStoredButNeverMatched() {
        // Matching a 128-bit MD5 against a malware corpus is a collision argument nobody wants.
        String md5 = "c0c7a5906bcd128b5db7f04ca82a54c1";
        seedMalwareHash("c24ccb6dd7f0b36890b5293f67ffc4756c01925db1532b5aca55fc0a2d0dc963", "Mirai", 1.0d);

        SBOMComponent component = component("md5-only", "1.0.0", "pkg:npm/md5-only@1.0.0");
        component.getHashes().add(ComponentHash.of("MD5", md5));
        detectionService.detect(sbomWith(component));

        assertThat(findingRepository.findAll()).isEmpty();
    }

    @Test
    @Transactional
    void aPackageThatIsBothMaliciousAndShipsAKnownMalwareFileGetsTwoFindings() {
        String digest = "1a2c3170e97283a0b285f563bed69e19df565dd4b524ff7f9d5a746ba7e6f71d";
        seedWholePackage("MAL-2026-3", "npm", "doubly-bad");
        seedMalwareHash(digest, "AgentTesla", 0.95d);

        SBOMComponent component = component("doubly-bad", "1.0.0", "pkg:npm/doubly-bad@1.0.0");
        component.getHashes().add(ComponentHash.of("SHA-256", digest));
        detectionService.detect(sbomWith(component));

        assertThat(findingRepository.findAll())
                .as("two separate facts with two separate pieces of evidence; collapsing them loses one")
                .hasSize(2)
                .extracting(CompromiseFinding::getType)
                .containsExactlyInAnyOrder(CompromiseType.MALICIOUS_PACKAGE, CompromiseType.MALWARE_HASH);
    }

    /* ---------------------------------------------------------------------- */
    /* Re-scan lifecycle                                                      */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void reDetectingUpdatesInPlaceRatherThanDuplicating() {
        seedWholePackage("MAL-2026-4502", "npm", "bad-pkg");
        SBOM sbom = sbomWith(component("bad-pkg", "1.0.0", "pkg:npm/bad-pkg@1.0.0"));

        assertThat(detectionService.detect(sbom).created()).isEqualTo(1);
        UUID firstId = onlyFinding().getId();

        CompromiseDetectionService.DetectionSummary second = detectionService.detect(sbom);
        assertThat(second.created()).isZero();
        assertThat(second.updated()).isEqualTo(1);
        assertThat(onlyFinding().getId())
                .as("keyed on (component identity, type, ioc id) — never a duplicate")
                .isEqualTo(firstId);
    }

    @Test
    @Transactional
    void aFindingAReScanNoLongerReproducesIsAutoResolvedNotDeleted() {
        MaliciousPackage bad = seedWholePackage("MAL-2026-4502", "npm", "bad-pkg");
        Product product = product("Acme Web");
        SBOM first = sbomWith(product, component("bad-pkg", "1.0.0", "pkg:npm/bad-pkg@1.0.0"));

        detectionService.detect(first);
        assertThat(onlyFinding().getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);

        // The operator ripped the package out and re-uploaded. Same product, new SBOM, new
        // component rows — which is exactly the case a component-id-keyed reconciliation would miss.
        maliciousPackageRepository.delete(bad);
        SBOM second = sbomWith(product, component("innocent-pkg", "2.0.0", "pkg:npm/innocent-pkg@2.0.0"));

        CompromiseDetectionService.DetectionSummary summary = detectionService.detect(second);

        assertThat(summary.autoResolved()).isEqualTo(1);
        assertThat(findingRepository.findAll())
                .as("evidence is never deleted — Phase 2's rule, unchanged")
                .hasSize(1);
        assertThat(onlyFinding().getLifecycleState()).isEqualTo(AlertLifecycleState.AUTO_RESOLVED);
    }

    @Test
    @Transactional
    void aReturningMatchRevivesTheSameRowRatherThanRaisingANewOne() {
        Product product = product("Acme Web");
        MaliciousPackage bad = seedWholePackage("MAL-2026-4502", "npm", "bad-pkg");

        detectionService.detect(sbomWith(product, component("bad-pkg", "1.0.0", "pkg:npm/bad-pkg@1.0.0")));
        UUID findingId = onlyFinding().getId();

        maliciousPackageRepository.delete(bad);
        detectionService.detect(sbomWith(product, component("other", "1.0.0", "pkg:npm/other@1.0.0")));
        assertThat(onlyFinding().getLifecycleState()).isEqualTo(AlertLifecycleState.AUTO_RESOLVED);

        seedWholePackage("MAL-2026-4502", "npm", "bad-pkg");
        detectionService.detect(sbomWith(product, component("bad-pkg", "1.0.0", "pkg:npm/bad-pkg@1.0.0")));

        assertThat(findingRepository.findAll()).hasSize(1);
        assertThat(onlyFinding().getId()).isEqualTo(findingId);
        assertThat(onlyFinding().getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
    }

    /* ---------------------------------------------------------------------- */
    /* Detection honours IOC aging                                            */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void detectionAppliesTheStalenessRuleSoItCannotFightTheNightlySweep() {
        // Without this, detection would re-derive CONFIRMED on every upload and undo whatever
        // CompromiseAgingService had just demoted — the finding would flip depending on which ran
        // last. Both go through CompromiseAgingService.applyAging.
        MaliciousPackage ancient = seedWholePackage("MAL-2019-1", "npm", "ancient-pkg");
        ancient.setIocFirstSeen(LocalDateTime.now().minusDays(400));
        ancient.setIocLastSeen(LocalDateTime.now().minusDays(400));
        maliciousPackageRepository.save(ancient);

        detectionService.detect(sbomWith(component("ancient-pkg", "1.0.0", "pkg:npm/ancient-pkg@1.0.0")));

        CompromiseFinding finding = onlyFinding();
        assertThat(finding.getConfidence())
                .as("the evidence says CONFIRMED, but the IOC is 400 days stale")
                .isEqualTo(CompromiseConfidence.INVESTIGATE);
        assertThat(finding.getAgedAt()).isNotNull();
    }

    /* ---------------------------------------------------------------------- */
    /* Fixtures                                                               */
    /* ---------------------------------------------------------------------- */

    private CompromiseFinding onlyFinding() {
        List<CompromiseFinding> all = findingRepository.findAll();
        assertThat(all).hasSize(1);
        return all.get(0);
    }

    /** The common shape: one unbounded {@code introduced: "0"} range, i.e. "all versions". */
    private MaliciousPackage seedWholePackage(String malId, String ecosystem, String name) {
        MaliciousPackage row = new MaliciousPackage();
        row.setMalId(malId);
        row.setEcosystem(ecosystem);
        row.setPackageName(name);
        row.setSummary("Malicious code in " + name + " (" + ecosystem + ")");
        row.setDetails("Seeded by CompromiseDetectionServiceTest.");
        row.setOrigins("ghsa-malware");
        row.setIocFirstSeen(LocalDateTime.now().minusDays(3));
        row.setIocLastSeen(LocalDateTime.now().minusDays(1));

        MaliciousPackageRange range = new MaliciousPackageRange();
        range.setRangeType("SEMVER");
        range.setIntroduced("0");
        range.setMaliciousPackage(row);
        row.getRanges().add(range);

        return maliciousPackageRepository.saveAndFlush(row);
    }

    private void seedMalwareHash(String sha256, String signature, double confidence) {
        MalwareHash hash = new MalwareHash();
        hash.setSha256(sha256);
        hash.setSignature(signature);
        hash.setReporter("abuse_ch");
        hash.setFirstSeen(LocalDateTime.now().minusDays(2));
        hash.setLastSeen(LocalDateTime.now().minusHours(1));
        hash.setConfidence(confidence);
        malwareHashRepository.saveAndFlush(hash);
    }

    private static SBOMComponent component(String name, String version, String purl) {
        SBOMComponent component = new SBOMComponent();
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        return component;
    }

    private Product product(String name) {
        Product product = new Product();
        product.setName(name);
        return productRepository.saveAndFlush(product);
    }

    private SBOM sbomWith(SBOMComponent... components) {
        return sbomWith(product("Test Product " + UUID.randomUUID()), components);
    }

    private SBOM sbomWith(Product product, SBOMComponent... components) {
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        for (SBOMComponent component : components) {
            component.setSbom(sbom);
            sbom.getComponents().add(component);
        }
        return sbomRepository.saveAndFlush(sbom);
    }

}
