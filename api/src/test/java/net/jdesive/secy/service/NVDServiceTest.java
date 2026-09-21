package net.jdesive.secy.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.nvd.NVDCVEResult;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMComponentRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * The regression this pins: {@link NVDService#saveVulnerabilities} re-ingesting a CVE that already
 * has a real {@link VulnerabilityAlert} against it used to throw
 * {@code HibernateException: A collection with cascade="all-delete-orphan" was no longer
 * referenced by the owning entity instance: Vulnerability.alerts} — reported against a real,
 * actively-correlating database, where every prior test happened to run against CVEs with no
 * alerts yet and so never exercised this path.
 *
 * <p>Root cause: {@code saveVulnerabilities} built a brand-new detached {@link Vulnerability} for
 * every CVE and saved it. Because {@code Vulnerability}'s {@code @Id} is manually assigned (no
 * {@code @GeneratedValue}), Spring Data's default {@code isNew()} check always routes {@code save()}
 * through {@code entityManager.merge(...)}. Merging an object whose {@code alerts} field is Java
 * {@code null} (it has no field initializer, unlike its sibling collections
 * {@code references}/{@code cpeOperators}) onto a managed entity that already has a real, tracked
 * {@code orphanRemoval=true} collection for that role is exactly what Hibernate refuses at flush
 * time. The fix loads the existing managed row first and mutates it in place, never touching
 * {@code alerts} at all.
 */
@SpringBootTest
class NVDServiceTest {

    private static final String CVE_ID = "CVE-2021-44228";

    @Autowired
    private NVDService nvdService;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulnerabilityAlertRepository vulnerabilityAlertRepository;

    @Autowired
    private SBOMComponentRepository sbomComponentRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * A minimal, hand-built NVD 2.0 API response for one CVE. {@code metrics} must be present (even
     * empty) — {@code saveVulnerabilities} calls {@code getMetrics().getCvssMetricV2()} with no
     * null-check on {@code getMetrics()} itself.
     */
    private static String nvdResultJson(String lastModified) {
        return """
                {
                  "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
                  "vulnerabilities": [
                    { "cve": {
                        "id": "%s",
                        "sourceIdentifier": "security@apache.org",
                        "published": "2021-12-10T10:15:09.143",
                        "lastModified": "%s",
                        "vulnStatus": "Analyzed",
                        "descriptions": [ { "lang": "en", "value": "Updated description text." } ],
                        "metrics": {}
                    } }
                  ]
                }
                """.formatted(CVE_ID, lastModified);
    }

    @Test
    @Transactional
    void reIngestingACveWithARealAlertDoesNotThrowAndLeavesTheAlertInPlace() throws Exception {
        Product product = new Product();
        product.setName("re-ingest-nvd-test-" + UUID.randomUUID());
        product.setCreatedAt(LocalDateTime.now());
        product = productRepository.save(product);

        SBOM sbom = new SBOM();
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.5");
        sbom.setProduct(product);
        sbom = sbomRepository.save(sbom);

        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        component.setSbom(sbom);
        component = sbomComponentRepository.save(component);

        // The CVE, pre-existing exactly as NVD's own ingest would have originally created it.
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setId(CVE_ID);
        vulnerability.setDescription("Original description.");
        vulnerabilityRepository.save(vulnerability);

        // A real alert already correlated against it — this is the piece every earlier test ran
        // without, since it always ingested into an empty table.
        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(vulnerability);
        alert.setComponent(component);
        alert = vulnerabilityAlertRepository.save(alert);
        UUID alertId = alert.getId();

        NVDCVEResult result = objectMapper.readValue(
                nvdResultJson("2023-11-07T03:39:22.140"), NVDCVEResult.class);

        assertThatCode(() -> nvdService.saveVulnerabilities(result)).doesNotThrowAnyException();

        Vulnerability reloaded = vulnerabilityRepository.findById(CVE_ID).orElseThrow();
        assertThat(reloaded.getDescription()).isEqualTo("Updated description text.");

        // The alert must still exist, still pointing at the same CVE and component -- a re-ingest
        // must never silently orphan-delete alerts it has no business touching.
        VulnerabilityAlert stillThere = vulnerabilityAlertRepository.findById(alertId).orElseThrow();
        assertThat(stillThere.getVulnerability().getId()).isEqualTo(CVE_ID);
        assertThat(stillThere.getComponent().getId()).isEqualTo(component.getId());
        assertThat(vulnerabilityAlertRepository.count()).isEqualTo(1);
    }

    @Test
    @Transactional
    void savingABrandNewCveStillWorks() throws Exception {
        NVDCVEResult result = objectMapper.readValue(
                nvdResultJson("2023-11-07T03:39:22.140"), NVDCVEResult.class);

        int written = nvdService.saveVulnerabilities(result);

        assertThat(written).isEqualTo(1);
        assertThat(vulnerabilityRepository.findById(CVE_ID)).isPresent();
    }

}
