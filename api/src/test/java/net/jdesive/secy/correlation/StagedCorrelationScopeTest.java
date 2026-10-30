package net.jdesive.secy.correlation;

import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.MaliciousPackageRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.EPSS;
import net.jdesive.secy.persistence.entity.MaliciousPackage;
import net.jdesive.secy.persistence.entity.MaliciousPackageRange;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The highest-risk change in M1e: correlation/compromise-detection scope for a staged, product-
 * scoped SBOM. Without {@link SbomCorrelationScope}, relaxing the active-SBOM slot from
 * one-per-product to one-per-(product,stage) would let a new Build SBOM auto-resolve every alert on
 * a Source-only component, reviving on the next Source upload — flip-flopping forever. These tests
 * pin that this cannot happen and that "most-downstream stage wins" behaves as documented.
 */
@SpringBootTest
@Transactional
class StagedCorrelationScopeTest {

    @Autowired
    private CorrelationService correlationService;

    @Autowired
    private CompromiseDetectionService compromiseDetectionService;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private MaliciousPackageRepository maliciousPackageRepository;

    @Autowired
    private CompromiseFindingRepository findingRepository;

    /* ------------------------------------------------------------------ */
    /* 1. Downstream-wins, order-independent                              */
    /* ------------------------------------------------------------------ */

    @Test
    void mostDownstreamStageWinsForASharedIdentityRegardlessOfCorrelationOrder() {
        cve("CVE-2199-1001", 0.9f);
        advisory("GHSA-a", "npm", "pkg-a", "CVE-2199-1001", "0", "2.0.0");
        cve("CVE-2199-1002", 0.9f);
        advisory("GHSA-b", "npm", "pkg-b", "CVE-2199-1002", "0", "2.0.0");

        Product product = product();
        SBOM source = sbomInProduct(product, SbomLifecycleStage.SOURCE,
                component("pkg:npm/pkg-a@1.0.0", "pkg-a", "1.0.0"),
                component("pkg:npm/pkg-b@1.0.0", "pkg-b", "1.0.0"));
        SBOM build = sbomInProduct(product, SbomLifecycleStage.BUILD,
                component("pkg:npm/pkg-b@1.0.0", "pkg-b", "1.0.0"));

        correlate(source);
        correlate(build);

        List<VulnerabilityAlert> alerts = alertRepository.findAllByProductIdForCorrelation(product.getId());
        assertThat(alerts).hasSize(2);

        VulnerabilityAlert alertA = onlyAlertFor(alerts, "CVE-2199-1001");
        assertThat(alertA.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(alertA.getComponent().getSbom().getId()).isEqualTo(source.getId());

        VulnerabilityAlert alertB = onlyAlertFor(alerts, "CVE-2199-1002");
        assertThat(alertB.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(alertB.getComponent().getSbom().getId())
                .as("Build is downstream of Source, so its row wins for the shared identity")
                .isEqualTo(build.getId());

        // Re-correlating Source must not disturb pkg-b's alert or duplicate anything.
        correlate(source);
        List<VulnerabilityAlert> afterReCorrelate =
                alertRepository.findAllByProductIdForCorrelation(product.getId());
        assertThat(afterReCorrelate).hasSize(2);
        VulnerabilityAlert alertBAfter = onlyAlertFor(afterReCorrelate, "CVE-2199-1002");
        assertThat(alertBAfter.getId()).isEqualTo(alertB.getId());
        assertThat(alertBAfter.getComponent().getSbom().getId())
                .as("downstream wins regardless of correlation order")
                .isEqualTo(build.getId());
    }

    /* ------------------------------------------------------------------ */
    /* 2. Superseding a stage re-points, doesn't lose, the alert           */
    /* ------------------------------------------------------------------ */

    @Test
    void aNewBuildWithoutTheVulnerablePackageRePointsTheAlertBackToSource() {
        cve("CVE-2199-2001", 0.9f);
        advisory("GHSA-c", "npm", "pkg-c", "CVE-2199-2001", "0", "2.0.0");

        Product product = product();
        SBOM source = sbomInProduct(product, SbomLifecycleStage.SOURCE,
                component("pkg:npm/pkg-c@1.0.0", "pkg-c", "1.0.0"));
        SBOM oldBuild = sbomInProduct(product, SbomLifecycleStage.BUILD,
                component("pkg:npm/pkg-c@1.0.0", "pkg-c", "1.0.0"));

        correlate(source);
        correlate(oldBuild);

        List<VulnerabilityAlert> beforeAlerts = alertRepository.findAllByProductIdForCorrelation(product.getId());
        assertThat(beforeAlerts).hasSize(1);
        UUID alertId = beforeAlerts.get(0).getId();
        assertThat(beforeAlerts.get(0).getComponent().getSbom().getId()).isEqualTo(oldBuild.getId());

        // Old Build superseded by a new Build that no longer ships pkg-c. Deactivate the old build
        // manually (mirrors SBOMService.deactivateSupersededSboms without going through the upload
        // path), Source stays as-is.
        oldBuild.setActive(false);
        sbomRepository.saveAndFlush(oldBuild);
        SBOM newBuild = sbomInProduct(product, SbomLifecycleStage.BUILD,
                component("pkg:npm/unrelated@1.0.0", "unrelated", "1.0.0"));

        correlate(newBuild);

        List<VulnerabilityAlert> afterAlerts = alertRepository.findAllByProductIdForCorrelation(product.getId());
        assertThat(afterAlerts).hasSize(1);
        assertThat(afterAlerts.get(0).getId()).isEqualTo(alertId);
        assertThat(afterAlerts.get(0).getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(afterAlerts.get(0).getComponent().getSbom().getId())
                .as("no active Build ships pkg-c any more, so the alert re-points to Source's own row")
                .isEqualTo(source.getId());
    }

    /* ------------------------------------------------------------------ */
    /* 3. KEV data precondition: lifecycleStage is readable off the alert  */
    /* ------------------------------------------------------------------ */

    @Test
    void deployedAndSourceOnlyAlertsCarryTheirOwnDistinctLifecycleStage() {
        cve("CVE-2199-3001", 0.9f);
        advisory("GHSA-deployed", "npm", "pkg-x", "CVE-2199-3001", "0", "2.0.0");
        cve("CVE-2199-3002", 0.9f);
        advisory("GHSA-sourceonly", "npm", "pkg-y", "CVE-2199-3002", "0", "2.0.0");

        Product product = product();
        SBOM source = sbomInProduct(product, SbomLifecycleStage.SOURCE,
                component("pkg:npm/pkg-x@1.0.0", "pkg-x", "1.0.0"),
                component("pkg:npm/pkg-y@1.0.0", "pkg-y", "1.0.0"));
        SBOM build = sbomInProduct(product, SbomLifecycleStage.BUILD,
                component("pkg:npm/pkg-x@1.0.0", "pkg-x", "1.0.0"));
        SBOM deployed = sbomInProduct(product, SbomLifecycleStage.DEPLOYED,
                component("pkg:npm/pkg-x@1.0.0", "pkg-x", "1.0.0"));

        correlate(source);
        correlate(build);
        correlate(deployed);

        List<VulnerabilityAlert> alerts = alertRepository.findAllByProductIdForCorrelation(product.getId());
        VulnerabilityAlert deployedAlert = onlyAlertFor(alerts, "CVE-2199-3001");
        assertThat(deployedAlert.getComponent().getSbom().getLifecycleStage())
                .isEqualTo(SbomLifecycleStage.DEPLOYED);

        VulnerabilityAlert sourceOnlyAlert = onlyAlertFor(alerts, "CVE-2199-3002");
        assertThat(sourceOnlyAlert.getComponent().getSbom().getLifecycleStage())
                .isEqualTo(SbomLifecycleStage.SOURCE);
    }

    /* ------------------------------------------------------------------ */
    /* 4. Unstaged guard — identical to pre-M1e behaviour                 */
    /* ------------------------------------------------------------------ */

    @Test
    void twoHandBuiltActiveUnstagedSbomsAutoResolveEachOtherJustLikeBeforeM1e() {
        cve("CVE-2199-4001", 0.9f);
        advisory("GHSA-unstaged", "npm", "pkg-z", "CVE-2199-4001", "0", "2.0.0");

        Product product = product();
        SBOM first = sbomInProduct(product, null, component("pkg:npm/pkg-z@1.0.0", "pkg-z", "1.0.0"));
        correlate(first);
        assertThat(alertRepository.findAllByProductIdForCorrelation(product.getId())).hasSize(1);

        // Hand-built second active unstaged SBOM without going through SBOMService (bypasses the
        // slot invariant on purpose, mirroring a pre-existing/legacy row).
        SBOM second = sbomInProduct(product, null, component("pkg:npm/unrelated@1.0.0", "unrelated", "1.0.0"));

        correlate(second);

        List<VulnerabilityAlert> after = alertRepository.findAllByProductIdForCorrelation(product.getId());
        assertThat(after).hasSize(1);
        assertThat(after.get(0).getLifecycleState())
                .as("unstaged SBOMs still reconcile at whole-product scope, exactly as before M1e")
                .isEqualTo(AlertLifecycleState.AUTO_RESOLVED);
    }

    /* ------------------------------------------------------------------ */
    /* 5. Compromise detection: same unstaged/staged scope split           */
    /* ------------------------------------------------------------------ */

    @Test
    void aMaliciousPackageOnlyInSourceStaysActiveWhenDetectingOnBuild() {
        seedWholePackage("MAL-2199-0001", "npm", "evil-pkg");

        Product product = product();
        SBOM source = sbomInProduct(product, SbomLifecycleStage.SOURCE,
                component("pkg:npm/evil-pkg@1.0.0", "evil-pkg", "1.0.0"));
        SBOM build = sbomInProduct(product, SbomLifecycleStage.BUILD,
                component("pkg:npm/clean-pkg@1.0.0", "clean-pkg", "1.0.0"));

        compromiseDetectionService.detect(reload(source));
        assertThat(findingRepository.findAllByProductIdForDetection(product.getId())).hasSize(1);

        compromiseDetectionService.detect(reload(build));

        List<CompromiseFinding> after = findingRepository.findAllByProductIdForDetection(product.getId());
        assertThat(after).hasSize(1);
        assertThat(after.get(0).getLifecycleState())
                .as("Source's evil-pkg is still in scope via the staged union, so detecting Build must not "
                        + "auto-resolve it")
                .isEqualTo(AlertLifecycleState.ACTIVE);
    }

    /* ------------------------------------------------------------------ */
    /* 6. The bucket with staged SBOMs: still SBOM-scoped, no cross-talk   */
    /* ------------------------------------------------------------------ */

    @Test
    void aBucketProductWithStagedSbomsStaysSbomScoped() {
        cve("CVE-2199-6001", 0.9f);
        advisory("GHSA-bucket-staged-a", "npm", "bucket-staged-a", "CVE-2199-6001", "0", "2.0.0");
        cve("CVE-2199-6002", 0.9f);
        advisory("GHSA-bucket-staged-b", "npm", "bucket-staged-b", "CVE-2199-6002", "0", "2.0.0");

        Product bucket = new Product();
        bucket.setName("staged-bucket-" + UUID.randomUUID());
        bucket.setUnassigned(true);
        bucket = productRepository.saveAndFlush(bucket);

        SBOM first = sbomInProduct(bucket, SbomLifecycleStage.SOURCE,
                component("pkg:npm/bucket-staged-a@1.0.0", "bucket-staged-a", "1.0.0"));
        correlate(first);
        assertThat(alertRepository.findAllBySbomIdForCorrelation(first.getId())).hasSize(1);

        SBOM second = sbomInProduct(bucket, SbomLifecycleStage.SOURCE,
                component("pkg:npm/bucket-staged-b@1.0.0", "bucket-staged-b", "1.0.0"));
        correlate(second);

        // The bucket is never product-scoped, whatever stage its SBOMs carry — each keeps its own
        // alert, untouched by the other's correlation.
        List<VulnerabilityAlert> firstAfter = alertRepository.findAllBySbomIdForCorrelation(first.getId());
        assertThat(firstAfter).hasSize(1);
        assertThat(firstAfter.get(0).getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(alertRepository.findAllBySbomIdForCorrelation(second.getId())).hasSize(1);
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private void correlate(SBOM sbom) {
        correlationService.correlate(reload(sbom));
    }

    private SBOM reload(SBOM sbom) {
        return sbomRepository.findByIdWithComponents(sbom.getId()).orElseThrow();
    }

    private VulnerabilityAlert onlyAlertFor(List<VulnerabilityAlert> alerts, String cveId) {
        List<VulnerabilityAlert> matches = alerts.stream()
                .filter(a -> a.getVulnerability().getId().equals(cveId))
                .toList();
        assertThat(matches).as("exactly one alert for %s", cveId).hasSize(1);
        return matches.get(0);
    }

    private Product product() {
        Product product = new Product();
        product.setName("staged-scope-" + UUID.randomUUID());
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

    private void cve(String id, float epssScore) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for StagedCorrelationScopeTest");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.5d);
        cveRepository.save(cve);

        EPSS epss = new EPSS();
        epss.setCve(id);
        epss.setEpss(epssScore);
        epss.setPercentile(0.99f);
        epss.setDate(LocalDateTime.now());
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

    private MaliciousPackage seedWholePackage(String malId, String ecosystem, String name) {
        MaliciousPackage row = new MaliciousPackage();
        row.setMalId(malId);
        row.setEcosystem(ecosystem);
        row.setPackageName(name);
        row.setSummary("Malicious code in " + name + " (" + ecosystem + ")");
        row.setDetails("Seeded by StagedCorrelationScopeTest.");
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

}
