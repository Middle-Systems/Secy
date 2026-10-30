package net.jdesive.secy.correlation;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.CveStatus;
import net.jdesive.secy.persistence.entity.IdentityConfidence;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
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

/**
 * Proves M1c's core independence claim end to end (ROADMAP.md — "Canonical component identity"):
 * a component's {@link IdentityConfidence} (M1c, CVE-independent, document-facts-only) and an
 * alert's {@link MatchConfidence} (Phase 4, per-CVE) are computed from different inputs and never
 * influence one another. A component whose own declared CPE flatly contradicts its PURL still
 * correlates exactly as if that CPE were never declared — {@code identityConfidence == CONFLICTING}
 * and {@code matchConfidence == EXACT} coexist on the very same alert.
 *
 * <p>Uses the same lodash 4.17.20/OSV-range/4.17.21-fix world as {@code CorrelationGoldenTest}'s
 * fixture 01 and {@code ComponentIdentityLifecycleTest}, but driven through the real
 * {@code SBOMService.ingestDocument} path (unlike the golden set, which bypasses the normalizer) so
 * M1c's identifier parsing and Pass A assessment actually run.
 */
@SpringBootTest
@Transactional
class IdentityConflictCorrelationInvarianceTest {

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
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void aConflictingDeclaredCpeDoesNotChangeTheAlertOrItsMatchConfidence() throws Exception {
        osvRepository.deleteAll();

        Vulnerability cve = new Vulnerability();
        cve.setId("CVE-2021-23337");
        cve.setDescription("Command injection in lodash");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.2d);
        cve.setCveStatus(CveStatus.PUBLISHED);
        cveRepository.save(cve);

        OsvAdvisory advisory = new OsvAdvisory();
        advisory.setOsvId("GHSA-35jh-r3h4-6jhm");
        advisory.setEcosystem("npm");
        advisory.setPackageName("lodash");
        advisory.setModified(LocalDateTime.now());
        advisory.setLastIngestedAt(LocalDateTime.now());
        advisory.getAliases().add("CVE-2021-23337");
        advisory.getVersions().add("4.17.20");
        OsvAffectedRange range = new OsvAffectedRange();
        range.setAdvisory(advisory);
        range.setRangeType("ECOSYSTEM");
        range.setIntroduced("0");
        range.setFixed("4.17.21");
        advisory.getRanges().add(range);
        osvRepository.save(advisory);

        Product product = new Product();
        product.setName("identity-invariance-" + UUID.randomUUID());
        product = productRepository.save(product);

        entityManager.flush();
        entityManager.clear();

        String json = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "lodash",
                      "version": "4.17.20",
                      "purl": "pkg:npm/lodash@4.17.20",
                      "cpe": "cpe:2.3:a:python:python:3.9.0:*:*:*:*:*:*:*"
                    }
                  ]
                }
                """;

        NormalizedSbom document = sbomParser.parse(mapper.readTree(json));
        SBOM placeholder = sbomService.createPlaceholder(product, document, "1.0.0", json, null,
                SbomIngestionSource.MANUAL_UPLOAD, null);
        sbomService.ingestDocument(placeholder, document, JobProgress.NOOP);
        entityManager.flush();
        entityManager.clear();

        UUID sbomId = placeholder.getId();
        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        assertThat(sbom.getComponents()).hasSize(1);
        assertThat(sbom.getComponents().get(0).getIdentityConfidence())
                .as("the declared CPE flatly contradicts the PURL")
                .isEqualTo(IdentityConfidence.CONFLICTING);

        correlationService.correlate(sbom);
        entityManager.flush();
        entityManager.clear();

        List<VulnerabilityAlert> alerts = alertRepository.findAllBySbomIdForCorrelation(sbomId);
        assertThat(alerts).as("identity conflict must not suppress, duplicate or alter the alert").hasSize(1);

        VulnerabilityAlert alert = alerts.get(0);
        assertThat(alert.getVulnerability().getId()).isEqualTo("CVE-2021-23337");
        assertThat(alert.getMatchConfidence())
                .as("MatchConfidence is untouched by identity confidence")
                .isEqualTo(MatchConfidence.EXACT);
        assertThat(alert.getFixedVersions()).isEqualTo("4.17.21");
        assertThat(alert.getComponent().getIdentityConfidence())
                .as("the two confidences coexist on the very same alert's component")
                .isEqualTo(IdentityConfidence.CONFLICTING);
    }

}
