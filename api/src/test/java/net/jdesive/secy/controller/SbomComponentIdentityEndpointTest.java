package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.CveStatus;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.service.SBOMService;
import net.jdesive.secy.service.sbom.SbomParser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /sbom/{sbomId}/components/{componentId}/identity} (M1c, ROADMAP.md — "Canonical
 * component identity") and the accompanying regression guard on
 * {@code GET /sbom/{sbomId}/vulnerabilities}: {@code identityConfidence} is now a visible field on
 * every serialized {@code SBOMComponent}, while {@code identifiers}/{@code identityConflicts} stay
 * {@code @JsonIgnore}d — the identity endpoint is the only read path for those.
 *
 * <p>Data is seeded directly through {@link SBOMService}/{@code CorrelationService}, the same real
 * ingest path {@code ComponentIdentityIngestTest} drives; {@link MockMvc} is used only for the HTTP
 * surface under test.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
@Transactional
class SbomComponentIdentityEndpointTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SbomParser sbomParser;

    @Autowired
    private SBOMService sbomService;

    @Autowired
    private net.jdesive.secy.correlation.CorrelationService correlationService;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void theIdentityEndpointReturnsEverythingTheVulnerabilitiesEndpointHides() throws Exception {
        osvRepository.deleteAll();

        Vulnerability cve = new Vulnerability();
        cve.setId("CVE-2021-23337");
        cve.setDescription("Command injection in lodash");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.2d);
        cve.setCveStatus(CveStatus.PUBLISHED);
        cveRepository.save(cve);

        OsvAdvisory advisory = new OsvAdvisory();
        advisory.setOsvId("GHSA-endpoint-lodash");
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
        product.setName("identity-endpoint-" + UUID.randomUUID());
        product = productRepository.save(product);

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
                      "cpe": "cpe:2.3:a:apache:lodash:4.17.20:*:*:*:*:*:*:*"
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
        correlationService.correlate(sbomRepository.findByIdWithComponents(sbomId).orElseThrow());
        entityManager.flush();
        entityManager.clear();

        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        SBOMComponent component = sbom.getComponents().get(0);
        UUID componentId = component.getId();

        mockMvc.perform(get("/sbom/{sbomId}/components/{componentId}/identity", sbomId, componentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.componentId").value(componentId.toString()))
                .andExpect(jsonPath("$.sbomId").value(sbomId.toString()))
                .andExpect(jsonPath("$.identityKey").value("npm/lodash"))
                .andExpect(jsonPath("$.identityConfidence").value("CORROBORATED"))
                .andExpect(jsonPath("$.identifiers", org.hamcrest.Matchers.hasSize(1)))
                .andExpect(jsonPath("$.identifiers[0].type").value("CPE"))
                .andExpect(jsonPath("$.identifiers[0].source").value("cyclonedx:component.cpe"))
                .andExpect(jsonPath("$.conflicts", org.hamcrest.Matchers.hasSize(0)))
                .andExpect(jsonPath("$.provenance.ingestionSource").value("MANUAL_UPLOAD"))
                .andExpect(jsonPath("$.provenance.lifecycleStage").value(org.hamcrest.Matchers.nullValue()))
                .andExpect(jsonPath("$.provenance.sbomId").value(sbomId.toString()));

        // A component id that is real, but belongs to a different SBOM, must 404 rather than leak
        // cross-document.
        Product otherProduct = new Product();
        otherProduct.setName("identity-endpoint-other-" + UUID.randomUUID());
        otherProduct = productRepository.save(otherProduct);
        String otherJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "components": [ { "type": "library", "name": "other-comp", "version": "1.0.0" } ]
                }
                """;
        NormalizedSbom otherDocument = sbomParser.parse(mapper.readTree(otherJson));
        SBOM otherPlaceholder = sbomService.createPlaceholder(otherProduct, otherDocument, "1.0.0", otherJson, null,
                SbomIngestionSource.MANUAL_UPLOAD, null);
        sbomService.ingestDocument(otherPlaceholder, otherDocument, JobProgress.NOOP);
        entityManager.flush();
        entityManager.clear();

        UUID otherSbomId = otherPlaceholder.getId();
        mockMvc.perform(get("/sbom/{sbomId}/components/{componentId}/identity", otherSbomId, componentId))
                .andExpect(status().isNotFound());

        // The vulnerabilities endpoint shows identityConfidence but never the ignored collections.
        mockMvc.perform(get("/sbom/{sbomId}/vulnerabilities", sbomId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].component.identityConfidence").value("CORROBORATED"))
                .andExpect(jsonPath("$[0].component.identifiers").doesNotExist())
                .andExpect(jsonPath("$[0].component.identityConflicts").doesNotExist());
    }

}
