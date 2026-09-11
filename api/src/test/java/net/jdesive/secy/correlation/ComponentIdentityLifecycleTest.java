package net.jdesive.secy.correlation;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.model.component.ComponentIdentity;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CveStatus;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.SBOMService;
import net.jdesive.secy.service.sbom.SbomParser;
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
 * <b>The regression this phase exists for.</b>
 *
 * <p>Phase 2 shipped an alert lifecycle — {@code ACTIVE} ↔ {@code AUTO_RESOLVED}, "upsert, never
 * duplicate" — keyed on {@code (component_id, cveId)}. That key was only stable while an SBOM was
 * re-correlated <em>against itself</em>. Every upload writes fresh {@code sbom_component} rows, so a
 * genuinely new SBOM for the same product presented all-new component ids: correlation saw an empty
 * "already on record" set, raised a duplicate of every alert, and left the previous upload's alerts
 * ACTIVE forever. Upgrading a dependency never resolved anything, which is most of the point of
 * re-uploading an SBOM.
 *
 * <p>This test walks the three moves that prove the fix, across <em>two different SBOM formats</em>,
 * to show the identity is a property of the dependency and not of the document that declared it:
 *
 * <ol>
 *   <li><b>v1</b> (CycloneDX) ships {@code lodash 4.17.20}, which OSV says is vulnerable →
 *       one {@code ACTIVE} alert.</li>
 *   <li><b>v2</b> (SPDX 2.3) ships {@code lodash 4.17.21}, the fixed release → <b>the same row</b>
 *       becomes {@code AUTO_RESOLVED}. Not a second row, not an orphan.</li>
 *   <li><b>v3</b> (CycloneDX) rolls back to {@code 4.17.20} → <b>the same row</b> revives to
 *       {@code ACTIVE}.</li>
 * </ol>
 *
 * <p>The row count is asserted at every step and the alert's UUID is asserted to be unchanged: a
 * duplicate would satisfy every state assertion on its own and is exactly the failure mode being
 * ruled out.
 */
@SpringBootTest
@Transactional
class ComponentIdentityLifecycleTest {

    private static final String CVE = "CVE-2021-23337";
    private static final String VULNERABLE = "4.17.20";
    private static final String FIXED = "4.17.21";

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private SBOMService sbomService;

    @Autowired
    private SbomParser sbomParser;

    @Autowired
    private CorrelationService correlationService;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @PersistenceContext
    private EntityManager entityManager;

    private Product product;

    @BeforeEach
    void seed() {
        osvRepository.deleteAll();

        Vulnerability cve = cveRepository.findById(CVE).orElseGet(() -> {
            Vulnerability fresh = new Vulnerability();
            fresh.setId(CVE);
            return fresh;
        });
        cve.setDescription("Command injection in lodash");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.2d);
        cve.setCveStatus(CveStatus.PUBLISHED);
        cveRepository.save(cve);

        // lodash is vulnerable from the beginning of time until 4.17.21.
        OsvAdvisory advisory = new OsvAdvisory();
        advisory.setOsvId("GHSA-35jh-r3h4-6jhm");
        advisory.setEcosystem("npm");
        advisory.setPackageName("lodash");
        advisory.setModified(LocalDateTime.now());
        advisory.setLastIngestedAt(LocalDateTime.now());
        advisory.getAliases().add(CVE);
        OsvAffectedRange range = new OsvAffectedRange();
        range.setAdvisory(advisory);
        range.setRangeType("ECOSYSTEM");
        range.setIntroduced("0");
        range.setFixed(FIXED);
        advisory.getRanges().add(range);
        osvRepository.save(advisory);

        product = new Product();
        product.setName("identity-lifecycle-" + UUID.randomUUID());
        product = productRepository.save(product);

        entityManager.flush();
        entityManager.clear();
    }

    /* ------------------------------------------------------------------ */
    /* The headline                                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void anAlertSurvivesANewSbomUploadAndAutoResolvesWhenTheComponentIsUpgraded() {
        /* --- v1: CycloneDX, lodash 4.17.20 — vulnerable ---------------- */

        UUID v1 = upload(cycloneDx(VULNERABLE), "1.0.0");
        correlate(v1);

        List<VulnerabilityAlert> afterV1 = alertsForProduct();
        assertThat(afterV1).as("v1 raises exactly one alert").hasSize(1);

        VulnerabilityAlert alert = afterV1.get(0);
        UUID alertId = alert.getId();
        assertThat(alert.getVulnerability().getId()).isEqualTo(CVE);
        assertThat(alert.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(alert.getComponent().getVersion()).isEqualTo(VULNERABLE);
        assertThat(alert.getComponent().getSbom().getId()).isEqualTo(v1);
        UUID v1ComponentId = alert.getComponent().getId();

        /* --- v2: SPDX 2.3, lodash 4.17.21 — fixed ---------------------- */

        UUID v2 = upload(spdx(FIXED), "1.1.0");
        correlate(v2);

        List<VulnerabilityAlert> afterV2 = alertsForProduct();
        assertThat(afterV2)
                .as("upgrading the component must not raise a second alert for the same CVE")
                .hasSize(1);

        VulnerabilityAlert resolved = afterV2.get(0);
        assertThat(resolved.getId())
                .as("the v1 alert is carried forward, not orphaned and replaced")
                .isEqualTo(alertId);
        assertThat(resolved.getLifecycleState())
                .as("lodash 4.17.21 is not affected, so the alert auto-resolves")
                .isEqualTo(AlertLifecycleState.AUTO_RESOLVED);

        /* --- v3: CycloneDX again, back to 4.17.20 — revived ------------ */

        UUID v3 = upload(cycloneDx(VULNERABLE), "1.2.0");
        correlate(v3);

        List<VulnerabilityAlert> afterV3 = alertsForProduct();
        assertThat(afterV3).as("reintroducing the vulnerable version revives, never duplicates").hasSize(1);

        VulnerabilityAlert revived = afterV3.get(0);
        assertThat(revived.getId()).isEqualTo(alertId);
        assertThat(revived.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);

        // The alert cites the evidence that currently supports it — v3's component row, not v1's.
        assertThat(revived.getComponent().getSbom().getId()).isEqualTo(v3);
        assertThat(revived.getComponent().getId()).isNotEqualTo(v1ComponentId);
        assertThat(revived.getComponent().getVersion()).isEqualTo(VULNERABLE);

        // Three uploads, three sets of component rows: the SBOM-version history is intact. De-dup is
        // of identity, not of rows — sharing rows would erase the membership a history diff reads.
        // (Scoped to this product: the H2 database is shared by every @SpringBootTest context.)
        assertThat(sbomRepository.findByProductIdOrderByUploadDateDesc(product.getId()))
                .extracting(SBOM::getId)
                .containsExactlyInAnyOrder(v1, v2, v3);
        assertThat(lodashIn(v1).getId()).isNotEqualTo(lodashIn(v2).getId());
        assertThat(lodashIn(v2).getId()).isNotEqualTo(lodashIn(v3).getId());
    }

    /* ------------------------------------------------------------------ */
    /* The mechanism                                                      */
    /* ------------------------------------------------------------------ */

    @Test
    void theIdentityKeyIsStableAcrossVersionsAndAcrossFormats() {
        UUID v1 = upload(cycloneDx(VULNERABLE), "1.0.0");
        UUID v2 = upload(spdx(FIXED), "1.1.0");

        SBOMComponent fromCycloneDx = lodashIn(v1);
        SBOMComponent fromSpdx = lodashIn(v2);

        assertThat(fromCycloneDx.getIdentityKey())
                .as("the version-less PURL: a version bump is the SAME dependency, changed")
                .isEqualTo("npm/lodash");
        assertThat(fromSpdx.getIdentityKey())
                .as("a product that switches SBOM generators must not duplicate its alerts")
                .isEqualTo(fromCycloneDx.getIdentityKey());

        // Same identity, different rows, different versions. That is the whole design.
        assertThat(fromSpdx.getId()).isNotEqualTo(fromCycloneDx.getId());
        assertThat(fromCycloneDx.getVersion()).isEqualTo(VULNERABLE);
        assertThat(fromSpdx.getVersion()).isEqualTo(FIXED);
    }

    @Test
    void theIdentityKeyIsDerivedOnPersistSoNoWriterCanForgetIt() {
        // Built by hand, the way the golden-set fixtures and the Phase 4 scanner path will build it:
        // nothing sets identityKey, and it is still correct.
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.5");
        sbom.setVersion(1);
        sbom.setActive(true);
        sbom.setStatus("PROCESSING");
        sbom.setUploadDate(LocalDateTime.now());

        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        component.setSbom(sbom);
        sbom.getComponents().add(component);

        UUID sbomId = sbomRepository.saveAndFlush(sbom).getId();
        entityManager.clear();

        SBOMComponent reloaded = sbomRepository.findByIdWithComponents(sbomId).orElseThrow()
                .getComponents().get(0);
        assertThat(reloaded.getIdentityKey()).isEqualTo("maven/org.apache.logging.log4j:log4j-core");
        assertThat(reloaded.getIdentityKey())
                .isEqualTo(ComponentIdentity.keyOf(reloaded.getPurl(), reloaded.getName()));
    }

    @Test
    void aComponentWithNoPurlStillCarriesForwardOnItsName() {
        // The CPE-fallback population: no PURL, so identity falls back to the name. Without this the
        // whole no-PURL half of the corpus would re-duplicate on every upload.
        UUID v1 = upload(cycloneDxNoPurl("1.1.1g"), "1.0.0");
        UUID v2 = upload(cycloneDxNoPurl("1.1.1w"), "1.1.0");

        assertThat(componentNamed(v1, "OpenSSL").getIdentityKey()).isEqualTo("name/openssl");
        assertThat(componentNamed(v2, "OpenSSL").getIdentityKey())
                .isEqualTo(componentNamed(v1, "OpenSSL").getIdentityKey());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Drives the same two phases {@code SBOMController} / the {@code SBOM_UPLOAD} job do (Phase 3
     * moved the persistence half off the request thread and onto the job queue), just without going
     * through {@code JobRunner} — there is no real job row here, only a stand-in id for
     * {@link SBOMService#ingestUploadJob} to key its {@code findByJobId} lookup on.
     */
    private UUID upload(String json, String productVersion) {
        NormalizedSbom document;
        try {
            document = sbomParser.parse(mapper.readTree(json));
        } catch (Exception e) {
            throw new IllegalStateException("fixture is not valid JSON", e);
        }
        UUID jobId = UUID.randomUUID();
        UUID id = sbomService.createPlaceholder(product, document, productVersion, json, jobId).getId();
        sbomService.ingestUploadJob(jobId, net.jdesive.secy.model.ingest.JobProgress.NOOP);
        entityManager.flush();
        entityManager.clear();
        return id;
    }

    /**
     * Correlate exactly as {@code VulnerabilityScanner} does. The async listener that normally
     * triggers this never fires here: the test transaction does not commit (see the class
     * {@code @Transactional}), so the scan is driven explicitly and deterministically.
     */
    private void correlate(UUID sbomId) {
        correlationService.correlate(sbomRepository.findByIdWithComponents(sbomId).orElseThrow());
        entityManager.flush();
        entityManager.clear();
    }

    private List<VulnerabilityAlert> alertsForProduct() {
        return alertRepository.findAllByProductIdForCorrelation(product.getId());
    }

    private SBOMComponent lodashIn(UUID sbomId) {
        return componentNamed(sbomId, "lodash");
    }

    private SBOMComponent componentNamed(UUID sbomId, String name) {
        return sbomRepository.findByIdWithComponents(sbomId).orElseThrow().getComponents().stream()
                .filter(c -> name.equals(c.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no component named " + name + " in " + sbomId));
    }

    /* ------------------------------------------------------------------ */
    /* Documents                                                          */
    /* ------------------------------------------------------------------ */

    private static String cycloneDx(String lodashVersion) {
        return """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "metadata": { "component": { "type": "application", "name": "acme-web" } },
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "pkg:npm/lodash@%1$s",
                      "name": "lodash",
                      "version": "%1$s",
                      "purl": "pkg:npm/lodash@%1$s",
                      "licenses": [ { "license": { "id": "MIT" } } ]
                    }
                  ]
                }
                """.formatted(lodashVersion);
    }

    private static String cycloneDxNoPurl(String opensslVersion) {
        return """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "components": [
                    { "type": "library", "name": "OpenSSL", "version": "%s" }
                  ]
                }
                """.formatted(opensslVersion);
    }

    private static String spdx(String lodashVersion) {
        return """
                {
                  "spdxVersion": "SPDX-2.3",
                  "dataLicense": "CC0-1.0",
                  "SPDXID": "SPDXRef-DOCUMENT",
                  "name": "acme-web",
                  "creationInfo": { "created": "2026-09-10T10:00:00Z", "creators": [ "Tool: syft-0.98.0" ] },
                  "documentDescribes": [ "SPDXRef-Package-root" ],
                  "packages": [
                    {
                      "SPDXID": "SPDXRef-Package-root",
                      "name": "acme-web",
                      "versionInfo": "1.1.0",
                      "downloadLocation": "NOASSERTION",
                      "primaryPackagePurpose": "APPLICATION"
                    },
                    {
                      "SPDXID": "SPDXRef-Package-lodash",
                      "name": "lodash",
                      "versionInfo": "%1$s",
                      "downloadLocation": "NOASSERTION",
                      "licenseConcluded": "MIT",
                      "primaryPackagePurpose": "LIBRARY",
                      "externalRefs": [
                        {
                          "referenceCategory": "PACKAGE-MANAGER",
                          "referenceType": "purl",
                          "referenceLocator": "pkg:npm/lodash@%1$s"
                        }
                      ]
                    }
                  ]
                }
                """.formatted(lodashVersion);
    }

}
