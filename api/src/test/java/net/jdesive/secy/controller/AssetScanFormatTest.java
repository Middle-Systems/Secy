package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.entity.AssetType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The synchronous half of a scan upload: what is rejected, and that nothing is stored when it is.
 *
 * <p>The same contract {@code SbomUploadFormatTest} pins for SBOMs, and it matters for the same
 * reason: a {@code 202} is a promise that the work can succeed, so a document that can never be
 * ingested has to fail before anything is queued or written.
 *
 * <p>Counts are asserted as deltas, not absolutes: the H2 database is shared by every
 * {@code @SpringBootTest} context in the run, and this class's {@code @Transactional} rollback only
 * undoes its own writes.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AssetScanFormatTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private JobRepository jobRepository;

    private long assetsBefore;
    private long jobsBefore;

    @BeforeEach
    void baseline() {
        assetsBefore = assetRepository.count();
        jobsBefore = jobRepository.count();
    }

    @Test
    @WithMockUser
    void anArbitraryJsonDocumentIsRejected() throws Exception {
        mockMvc.perform(post("/assets/scan/trivy")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("not-a-scan.json")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("Not a Trivy scan report")));

        assertNothingWasStored();
    }

    @Test
    @WithMockUser
    void grypeOutputPostedToTheTrivyEndpointSaysSoRatherThanFailingObscurely() throws Exception {
        mockMvc.perform(post("/assets/scan/trivy")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("grype-image.json")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("/assets/scan/grype")));

        assertNothingWasStored();
    }

    @Test
    @WithMockUser
    void trivyOutputPostedToTheGrypeEndpointSaysSoToo() throws Exception {
        mockMvc.perform(post("/assets/scan/grype")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("trivy-image.json")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("/assets/scan/trivy")));

        assertNothingWasStored();
    }

    @Test
    @WithMockUser
    void aTrivyComplianceReportIsNotAVulnerabilityScan() throws Exception {
        // `trivy config` / a CIS benchmark also produces a top-level `Results` array, with a
        // completely different element shape. That document belongs to the Phase 5 compliance path;
        // accepting it here would create an asset full of nothing.
        mockMvc.perform(post("/assets/scan/trivy")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("trivy-compliance-report.json")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("Not a Trivy scan report")));

        assertNothingWasStored();
    }

    @Test
    @WithMockUser
    void aScanThatNamesNoTargetAndNoAssetNameIsRejected() throws Exception {
        mockMvc.perform(post("/assets/scan/grype")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"matches\":[]}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("No asset name")));

        assertNothingWasStored();
    }

    @Test
    @WithMockUser
    void anExplicitNameSuppliesWhatTheReportDoesNot() throws Exception {
        mockMvc.perform(post("/assets/scan/grype")
                        .param("name", "build-agent-format-test")
                        .param("type", "HOST")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"matches\":[]}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("ASSET_SCAN"));

        assertThat(assetRepository.findByTypeAndName(AssetType.HOST, "build-agent-format-test"))
                .isPresent();
    }

    /** A rejected document must leave neither an asset row nor a job behind. */
    private void assertNothingWasStored() {
        assertThat(assetRepository.count()).isEqualTo(assetsBefore);
        assertThat(jobRepository.count()).isEqualTo(jobsBefore);
    }

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("asset/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
