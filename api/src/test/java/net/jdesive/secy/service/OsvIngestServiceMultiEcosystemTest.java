package net.jdesive.secy.service;

import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.OsvEcosystemCursorRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * A distinct two-ecosystem context (a different {@code secy.osv.ecosystems} value gets its own
 * cached Spring context, same as any other {@code @TestPropertySource} variance) so the "one
 * ecosystem failing must not abort the others" resilience rule can be exercised end to end without
 * disturbing {@link OsvIngestServiceTest}'s single-ecosystem fixtures.
 */
@SpringBootTest
@TestPropertySource(properties = "secy.osv.ecosystems=npm,Maven")
class OsvIngestServiceMultiEcosystemTest {

    private static final String NPM_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";
    private static final String MAVEN_URL = "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip";

    @Autowired
    private OsvIngestService osvIngestService;

    @Autowired
    private OsvAdvisoryRepository osvAdvisoryRepository;

    @Autowired
    private OsvEcosystemCursorRepository cursorRepository;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer gcs;

    @BeforeEach
    void setUp() {
        osvAdvisoryRepository.deleteAll();
        cursorRepository.deleteAll();
        gcs = MockRestServiceServer.bindTo(restTemplate).build();
    }

    @Test
    void oneEcosystemFailingDoesNotAbortTheOthers() throws IOException {
        String npmRecord = """
                {
                  "id": "GHSA-npm-ok",
                  "modified": "2024-01-01T00:00:00Z",
                  "aliases": ["CVE-2021-0100"],
                  "summary": "npm is fine",
                  "affected": [
                    {"package": {"ecosystem": "npm", "name": "fine-pkg"}, "versions": ["1.0.0"]}
                  ]
                }
                """;

        gcs.expect(requestTo(NPM_URL)).andRespond(withSuccess(buildZip(npmRecord), zipType()));
        gcs.expect(requestTo(MAVEN_URL)).andRespond(withServerError());

        IngestResult result = osvIngestService.ingest(JobProgress.NOOP);
        gcs.verify();

        // The npm row landed despite Maven failing.
        assertThat(osvAdvisoryRepository.findByOsvId("GHSA-npm-ok")).hasSize(1);
        assertThat(cursorRepository.findById("npm")).isPresent();
        assertThat(cursorRepository.findById("Maven")).isEmpty();
        assertThat(result.itemsProcessed()).isEqualTo(1);
        assertThat(result.message()).contains("npm").contains("Maven");
    }

    @Test
    void everyEcosystemFailingThrows() {
        gcs.expect(requestTo(NPM_URL)).andRespond(withServerError());
        gcs.expect(requestTo(MAVEN_URL)).andRespond(withServerError());

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> osvIngestService.ingest(JobProgress.NOOP))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("every configured ecosystem");
    }

    private static MediaType zipType() {
        return MediaType.parseMediaType("application/zip");
    }

    private static byte[] buildZip(String json) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry("a.json"));
            zos.write(json.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return baos.toByteArray();
    }

}
