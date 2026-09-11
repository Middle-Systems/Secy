package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Product;
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
import java.util.UUID;

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
 */
/*
 * @Transactional is load-bearing here, not hygiene: the upload publishes an SbomUploadedEvent whose
 * listener is @TransactionalEventListener(AFTER_COMMIT) + @Async. Running the request inside the
 * test's transaction means it never commits, so no background scan thread is started to race the
 * next test's cleanup. What this class asserts — detection, storage and the 400 — is all decided
 * before that event would fire.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
@org.springframework.transaction.annotation.Transactional
class SbomUploadFormatTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    private UUID productId;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        alertRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();

        Product product = new Product();
        product.setName("upload-format-" + UUID.randomUUID());
        productId = productRepository.save(product).getId();
    }

    @Test
    void cycloneDxIsDetectedAndStoredAsCycloneDx() throws Exception {
        upload("cyclonedx-mixed.json")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.format").value("CycloneDX"))
                .andExpect(jsonPath("$.specVersion").value("1.5"))
                .andExpect(jsonPath("$.version").value(3))
                .andExpect(jsonPath("$.components.length()").value(3));
    }

    @Test
    void spdx22IsDetectedAndStoredAsSpdx() throws Exception {
        upload("spdx-2.2-minimal.json")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.format").value("SPDX"))
                // The SPDX revision goes in specVersion verbatim: SPDX states format and revision in
                // one field where CycloneDX uses two.
                .andExpect(jsonPath("$.specVersion").value("SPDX-2.2"))
                .andExpect(jsonPath("$.components.length()").value(2));
    }

    @Test
    void spdx23IsDetectedAndStoredAsSpdx() throws Exception {
        upload("spdx-2.3-mixed.json")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.format").value("SPDX"))
                .andExpect(jsonPath("$.specVersion").value("SPDX-2.3"))
                .andExpect(jsonPath("$.components.length()").value(3));
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

        org.assertj.core.api.Assertions.assertThat(sbomRepository.findAll())
                .as("a 400 must not leave a half-ingested SBOM behind")
                .isEmpty();
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
