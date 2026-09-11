package net.jdesive.secy.service;

import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.CveStatus;
import net.jdesive.secy.persistence.entity.Vulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The CVE List v5 / Vulnrichment ingest, with the GitHub releases API and the asset download both
 * stubbed at the transport (see {@code OsvIngestServiceTest} for the pattern this follows). Fixture
 * records live under {@code src/test/resources/cve-list/} — see {@code PHASE2-CONTRACT.md} §2 for
 * the field-by-field contract this pins.
 */
@SpringBootTest
@TestPropertySource(properties = "secy.cve-list.releases-api-url=https://mock-github.example/repos/CVEProject/cvelistV5/releases/latest")
class CveListIngestServiceTest {

    private static final String RELEASES_URL =
            "https://mock-github.example/repos/CVEProject/cvelistV5/releases/latest";

    private static final String ZIP_URL =
            "https://mock-assets.example/2026-09-10_all_CVEs_at_midnight.zip.zip";

    @Autowired
    private CveListIngestService cveListIngestService;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer github;

    @BeforeEach
    void setUp() {
        github = MockRestServiceServer.bindTo(restTemplate).build();
    }

    /* ---------------------------------------------------------------------- */
    /* CVSS precedence: NVD > CNA > ADP                                       */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void anExistingNvdScoreIsNeverOverwritten() throws IOException {
        seed("CVE-2024-1001", v -> {
            v.setCvssScore(9.8);
            v.setCvssSource(null);
        });

        expectOnePassOf("nvd-precedence-untouched.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        Vulnerability updated = mustFind("CVE-2024-1001");
        assertThat(updated.getCvssScore()).as("NVD-owned score must survive the CVE List pass").isEqualTo(9.8);
        assertThat(updated.getCvssSource()).isNull();
        // cwe is not precedence-guarded — it is still applied.
        assertThat(updated.getCwe()).isEqualTo("CWE-79");
    }

    @Test
    @Transactional
    void aRowWithNoPriorNvdScoreGetsTheCnaScore() throws IOException {
        seed("CVE-2024-1002", v -> {
            v.setCvssScore(0.0);
            v.setCvssSource(null);
        });

        expectOnePassOf("cna-score-applied.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        Vulnerability updated = mustFind("CVE-2024-1002");
        assertThat(updated.getCvssScore()).isEqualTo(8.8);
        assertThat(updated.getCvssSource()).isEqualTo("CNA");
    }

    @Test
    @Transactional
    void anAdpScoreIsUsedWhenNoCnaScoreIsPresent() throws IOException {
        seed("CVE-2024-1007", v -> {
            v.setCvssScore(0.0);
            v.setCvssSource(null);
        });

        expectOnePassOf("adp-cvss-fallback.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        Vulnerability updated = mustFind("CVE-2024-1007");
        assertThat(updated.getCvssScore()).isEqualTo(6.1);
        assertThat(updated.getCvssSource()).isEqualTo("ADP");
    }

    @Test
    @Transactional
    void aPriorCnaScoreIsNotDowngradedByAnAdpOnlyRecord() throws IOException {
        seed("CVE-2024-1008", v -> {
            v.setCvssScore(5.0);
            v.setCvssSource("CNA");
        });

        expectOnePassOf("cna-not-downgraded-by-adp.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        Vulnerability updated = mustFind("CVE-2024-1008");
        assertThat(updated.getCvssScore()).as("CNA outranks ADP; an ADP-only pull must not downgrade it").isEqualTo(5.0);
        assertThat(updated.getCvssSource()).isEqualTo("CNA");
    }

    /* ---------------------------------------------------------------------- */
    /* cveStatus                                                              */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void aRejectedStateMarksTheRowRejected() throws IOException {
        seed("CVE-2024-1003", v -> { });

        expectOnePassOf("rejected.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        assertThat(mustFind("CVE-2024-1003").getCveStatus()).isEqualTo(CveStatus.REJECTED);
        assertThat(mustFind("CVE-2024-1003").isExcludedFromFunnel()).isTrue();
    }

    @Test
    @Transactional
    void aDisputedTagMarksTheRowDisputed() throws IOException {
        seed("CVE-2024-1004", v -> { });

        expectOnePassOf("disputed.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        assertThat(mustFind("CVE-2024-1004").getCveStatus()).isEqualTo(CveStatus.DISPUTED);
        assertThat(mustFind("CVE-2024-1004").isExcludedFromFunnel()).isTrue();
    }

    @Test
    @Transactional
    void aPlainRecordStaysPublished() throws IOException {
        seed("CVE-2024-1002", v -> { });

        expectOnePassOf("cna-score-applied.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        assertThat(mustFind("CVE-2024-1002").getCveStatus()).isEqualTo(CveStatus.PUBLISHED);
        assertThat(mustFind("CVE-2024-1002").isExcludedFromFunnel()).isFalse();
    }

    /* ---------------------------------------------------------------------- */
    /* SSVC — parsed defensively against two shapes                          */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void ssvcIsPopulatedFromTheOptionsArrayShapeAsRawLowercaseTokens() throws IOException {
        seed("CVE-2024-1005", v -> { });

        expectOnePassOf("ssvc-options-shape.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        Vulnerability updated = mustFind("CVE-2024-1005");
        assertThat(updated.getSsvcExploitation()).isEqualTo("poc");
        assertThat(updated.getSsvcAutomatable()).isEqualTo("no");
        assertThat(updated.getSsvcTechnicalImpact()).isEqualTo("total");
    }

    @Test
    @Transactional
    void ssvcIsPopulatedFromTheFlatContentShapeToo() throws IOException {
        seed("CVE-2024-1006", v -> { });

        expectOnePassOf("ssvc-flat-content-shape.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        Vulnerability updated = mustFind("CVE-2024-1006");
        assertThat(updated.getSsvcExploitation()).isEqualTo("active");
        assertThat(updated.getSsvcAutomatable()).isEqualTo("yes");
        assertThat(updated.getSsvcTechnicalImpact()).isEqualTo("partial");
    }

    /* ---------------------------------------------------------------------- */
    /* cwe                                                                    */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void cweIsDedupedAndJoinedFromBothCnaAndAdp() throws IOException {
        seed("CVE-2024-1009", v -> { });

        expectOnePassOf("multi-cwe.json");
        cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        assertThat(mustFind("CVE-2024-1009").getCwe()).isEqualTo("CWE-79,CWE-89,CWE-200");
    }

    /* ---------------------------------------------------------------------- */
    /* Resilience: unknown CVE, malformed record                             */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void aCveNotYetInOurTableIsSkippedNotStubbed() throws IOException {
        // Deliberately not seeded — CVE List can know about a CVE before NVD does (contract §12.2).
        expectOnePassOf("unknown-cve.json");

        IngestResult result = cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        assertThat(vulnerabilityRepository.findById("CVE-2024-1099")).isEmpty();
        assertThat(result.itemsProcessed()).isZero();
    }

    @Test
    @Transactional
    void aMalformedRecordIsSkippedWithoutAbortingTheRun() throws IOException {
        seed("CVE-2024-1002", v -> { });

        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("malformed.json", readFixture("malformed-no-id.json"));
        entries.put("good.json", readFixture("cna-score-applied.json"));

        github.expect(requestTo(RELEASES_URL)).andRespond(withSuccess(releasesJson(), MediaType.APPLICATION_JSON));
        github.expect(requestTo(ZIP_URL)).andRespond(withSuccess(buildZip(entries), zipType()));

        IngestResult result = cveListIngestService.ingest(JobProgress.NOOP);
        github.verify();

        assertThat(result.itemsProcessed()).isEqualTo(1);
        assertThat(mustFind("CVE-2024-1002").getCvssScore()).isEqualTo(8.8);
    }

    /* ---------------------------------------------------------------------- */
    /* Fixtures / helpers                                                     */
    /* ---------------------------------------------------------------------- */

    private Vulnerability mustFind(String cveId) {
        return vulnerabilityRepository.findById(cveId)
                .orElseThrow(() -> new AssertionError("expected a vulnerabilities row for " + cveId));
    }

    /** Seed (or reuse) a minimal {@link Vulnerability} row, the way {@code NVDService} would have created it. */
    private Vulnerability seed(String cveId, java.util.function.Consumer<Vulnerability> customize) {
        Vulnerability vulnerability = vulnerabilityRepository.findById(cveId).orElseGet(Vulnerability::new);
        vulnerability.setId(cveId);
        customize.accept(vulnerability);
        return vulnerabilityRepository.save(vulnerability);
    }

    private void expectOnePassOf(String fixtureFile) throws IOException {
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put(fixtureFile, readFixture(fixtureFile));
        github.expect(requestTo(RELEASES_URL)).andRespond(withSuccess(releasesJson(), MediaType.APPLICATION_JSON));
        github.expect(requestTo(ZIP_URL)).andRespond(withSuccess(buildZip(entries), zipType()));
    }

    private static String releasesJson() {
        return """
                {
                  "tag_name": "2026-09-10",
                  "assets": [
                    {"name": "2026-09-10_all_CVEs_at_midnight.zip.zip",
                     "browser_download_url": "%s"}
                  ]
                }
                """.formatted(ZIP_URL);
    }

    private static String readFixture(String name) throws IOException {
        try (InputStream in = new ClassPathResource("cve-list/" + name).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static MediaType zipType() {
        return MediaType.parseMediaType("application/zip");
    }

    private static byte[] buildZip(Map<String, String> entries) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
        }
        return baos.toByteArray();
    }

}
