package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The upload contract for {@code POST /sbom/{productId}/sboms} now that one endpoint serves two
 * document formats.
 *
 * <p>The body is no longer bound to {@code CycloneDXFile} — it arrives as a raw {@code JsonNode},
 * {@code SbomParser} sniffs the format, and an unrecognised document is a {@code 400} carrying a
 * message that names what was wrong. That last part is the bit worth pinning: the previous
 * behaviour for an SPDX upload was a silently empty CycloneDX bind, i.e. a {@code 201} for an SBOM
 * with zero components, which is the worst possible answer.
 *
 * <p>Phase 3 also moved persistence + scan onto the {@code SBOM_UPLOAD} job queue, so a valid
 * document no longer answers {@code 201} with the full {@code SBOM} — it answers {@code 202} with a
 * {@code QUEUED} {@code Job} instead (see {@code SbomUploadJobFlowTest} for the job actually running
 * to completion). What this class still owns is the synchronous half: detection/format validation,
 * the placeholder row's immediate fields, and the 400 path storing nothing.
 */
/*
 * @Transactional is load-bearing here, not hygiene: even the placeholder-creation path leaves a
 * SbomUploadedEvent-publishing job for a background poller to eventually pick up in a live app;
 * running the request inside the test's transaction means it never commits, so nothing outside this
 * test observes the row. What this class asserts — detection, the placeholder's fields and the 400 —
 * is all decided before any of that would matter.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
@org.springframework.transaction.annotation.Transactional
class SbomUploadFormatTest {

    /**
     * Not used to seed anything — cleared because a {@code compromise_finding} left behind by
     * another test class holds an FK into {@code sbom_component} / {@code asset_component} and
     * would block the deletes below (Phase 6).
     */
    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    /**
     * Cleared, not seeded: a leftover asset from another test class in the shared H2 database would
     * otherwise hold a FK on a product this seed deletes.
     */
    @Autowired
    private net.jdesive.secy.persistence.AssetRepository assetRepository;

    private UUID productId;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();

        Product product = new Product();
        product.setName("upload-format-" + UUID.randomUUID());
        productId = productRepository.save(product).getId();
    }

    @Test
    void cycloneDxIsDetectedAndQueuedAsAPlaceholderSbom() throws Exception {
        String body = upload("cyclonedx-mixed.json")
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("SBOM_UPLOAD"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andReturn().getResponse().getContentAsString();

        SBOM placeholder = onlySbom();
        assertThat(placeholder.getFormat()).isEqualTo("CycloneDX");
        assertThat(placeholder.getSpecVersion()).isEqualTo("1.5");
        assertThat(placeholder.getVersion()).isEqualTo(3);
        assertThat(placeholder.getStatus()).isEqualTo("QUEUED");
        assertThat(placeholder.isActive()).isTrue();
        assertThat(placeholder.getComponents()).as("not ingested yet — that's the job's work").isEmpty();
        assertThat(placeholder.getJobId()).isNotNull();
        assertThat(body).contains(placeholder.getJobId().toString());
    }

    @Test
    void spdx22IsDetectedAndQueuedAsAPlaceholderSbom() throws Exception {
        upload("spdx-2.2-minimal.json").andExpect(status().isAccepted());

        SBOM placeholder = onlySbom();
        assertThat(placeholder.getFormat()).isEqualTo("SPDX");
        // The SPDX revision goes in specVersion verbatim: SPDX states format and revision in one
        // field where CycloneDX uses two.
        assertThat(placeholder.getSpecVersion()).isEqualTo("SPDX-2.2");
        assertThat(placeholder.getComponents()).isEmpty();
    }

    @Test
    void spdx23IsDetectedAndQueuedAsAPlaceholderSbom() throws Exception {
        upload("spdx-2.3-mixed.json").andExpect(status().isAccepted());

        SBOM placeholder = onlySbom();
        assertThat(placeholder.getFormat()).isEqualTo("SPDX");
        assertThat(placeholder.getSpecVersion()).isEqualTo("SPDX-2.3");
        assertThat(placeholder.getComponents()).isEmpty();
    }

    @Test
    void aDocumentThatIsNeitherFormatIs400WithAMessageNamingTheProblem() throws Exception {
        upload("not-an-sbom.json")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message",
                        org.hamcrest.Matchers.allOf(
                                org.hamcrest.Matchers.containsString("bomFormat"),
                                org.hamcrest.Matchers.containsString("spdxVersion"))));
    }

    @Test
    void anUnsupportedSpdxRevisionIs400NamingTheVersion() throws Exception {
        upload("spdx-3.0-unsupported.json")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", org.hamcrest.Matchers.containsString("SPDX-3.0")));
    }

    @Test
    void aRejectedUploadStoresNothing() throws Exception {
        upload("not-an-sbom.json").andExpect(status().isBadRequest());

        assertThat(sbomRepository.findAll())
                .as("a 400 must not leave a half-ingested SBOM behind")
                .isEmpty();
    }

    private SBOM onlySbom() {
        List<SBOM> all = sbomRepository.findAll();
        assertThat(all).hasSize(1);
        return all.get(0);
    }

    private org.springframework.test.web.servlet.ResultActions upload(String fixture) throws Exception {
        return mockMvc.perform(post("/sbom/{productId}/sboms", productId)
                .param("productVersion", "1.0.0")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(fixture)));
    }

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("sbom/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
