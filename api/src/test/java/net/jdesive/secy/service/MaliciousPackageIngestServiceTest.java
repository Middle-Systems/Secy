package net.jdesive.secy.service;

import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.MaliciousPackageRepository;
import net.jdesive.secy.persistence.entity.MaliciousPackage;
import net.jdesive.secy.persistence.entity.MaliciousPackageRange;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The OpenSSF Malicious Packages ingest, with the GitHub archive stubbed at the transport (the
 * pattern {@code OsvIngestServiceTest} follows) and its zip built in memory.
 *
 * <p>The fixture reproduces the <b>real</b> archive layout —
 * {@code malicious-packages-main/osv/malicious/<ecosystem>/<package>/MAL-YYYY-N.json} — and the real
 * record shapes, including {@code database_specific.malicious-packages-origins[]}, which is where
 * {@code origins} and the IOC timestamps come from. See {@code PHASE6-CONTRACT.md} §1.
 */
@SpringBootTest
class MaliciousPackageIngestServiceTest {

    private static final String ARCHIVE_URL =
            "https://codeload.github.com/ossf/malicious-packages/zip/refs/heads/main";

    @Autowired
    private MaliciousPackageIngestService ingestService;

    @Autowired
    private MaliciousPackageRepository repository;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer github;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
        github = MockRestServiceServer.bindTo(restTemplate).build();
    }

    /* ---------------------------------------------------------------------- */
    /* One pass over every shape the contract describes                       */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void oneIngestPassPopulatesEveryShapeTheContractDescribes() throws IOException {
        github.expect(requestTo(ARCHIVE_URL)).andRespond(withSuccess(buildZip(fixture()), zipType()));

        IngestResult result = ingestService.ingest(JobProgress.NOOP);
        github.verify();

        assertThat(result.itemsProcessed())
                .as("one row per (record, ecosystem, package): 1 PyPI + 2 for the two-package npm "
                        + "record + 1 bounded + 1 withdrawn. The withdrawn record DOES write a row — "
                        + "marked withdrawn so the matcher skips it, never deleted, so a reversal "
                        + "needs no re-import. Only the unmergable one writes nothing.")
                .isEqualTo(5);

        // The common shape: the whole package is malware, expressed as an unbounded introduced:"0".
        MaliciousPackage wholePackage = mustFind("MAL-2023-1638", "PyPI", "beautiulsoup4");
        assertThat(wholePackage.affectsAllVersions())
                .as("introduced:\"0\" with no fixed and no last_affected covers every version")
                .isTrue();
        assertThat(wholePackage.getVersions()).isEmpty();
        assertThat(wholePackage.getRanges()).hasSize(1);
        assertThat(wholePackage.getRanges().get(0).getIntroduced()).isEqualTo("0");
        assertThat(wholePackage.getSummary()).isEqualTo("Malicious code in beautiulsoup4 (PyPI)");
        assertThat(wholePackage.isCurrent()).isTrue();

        // origins[] -> the `origins` column and BOTH IOC timestamps. This is the data the roadmap
        // hoped `category` would carry; see the class note on MaliciousPackageIngestService.
        assertThat(wholePackage.getOrigins()).isEqualTo("checkmarx");
        assertThat(wholePackage.getIocFirstSeen()).isEqualTo(LocalDateTime.of(2023, 8, 21, 20, 12, 58));
        assertThat(wholePackage.getIocLastSeen()).isEqualTo(LocalDateTime.of(2023, 8, 21, 20, 12, 58));
        assertThat(wholePackage.getCategory())
                .as("the published corpus carries no category; the column stays null")
                .isNull();

        // Enumerated versions[] — the narrower, stronger statement. affectsAllVersions() must be
        // FALSE here even though the record also carries an introduced:"0" range, or a clean 1.0.0
        // of a package whose 1.0.1 was hijacked would be reported as malware.
        MaliciousPackage enumerated = mustFind("MAL-2026-4502", "npm", "bucket-protocol-sdk-v2");
        assertThat(enumerated.getVersions()).containsExactlyInAnyOrder("1.0.11", "1.0.26");
        assertThat(enumerated.affectsAllVersions()).isFalse();
        assertThat(enumerated.getOrigins())
                .as("distinct sources, in first-seen order")
                .isEqualTo("amazon-inspector, ghsa-malware");
        assertThat(enumerated.getIocFirstSeen()).isEqualTo(LocalDateTime.of(2026, 5, 20, 4, 4, 10));
        assertThat(enumerated.getIocLastSeen()).isEqualTo(LocalDateTime.of(2026, 5, 20, 4, 4, 30));
        assertThat(enumerated.getReferencesJson()).contains("https://www.npmjs.com/package");

        // A bounded range: malicious from 2.0.0 until 2.0.4 fixed it. Not "all versions".
        MaliciousPackage bounded = mustFind("MAL-2024-0001", "npm", "bounded-pkg");
        assertThat(bounded.affectsAllVersions()).isFalse();
        assertThat(bounded.getRanges())
                .extracting(MaliciousPackageRange::getIntroduced, MaliciousPackageRange::getFixed)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("2.0.0", "2.0.4"));

        // One record naming two packages -> two rows, both resolvable by the record id.
        assertThat(repository.findByMalId("MAL-2026-4502")).hasSize(2);
        assertThat(repository.findByMalId("MAL-2026-4502"))
                .extracting(MaliciousPackage::getPackageName)
                .containsExactlyInAnyOrder("bucket-protocol-sdk-v2", "bucket-protocol-sdk-v3");

        // Withdrawn: stored with its timestamp, not deleted, so a reversal needs no re-import.
        MaliciousPackage withdrawn = mustFind("MAL-2022-0009", "npm", "withdrawn-pkg");
        assertThat(withdrawn.isCurrent()).isFalse();
        assertThat(withdrawn.getWithdrawn()).isNotNull();

        // unmergable/ is dropped entirely — no agreed package identity to match on.
        assertThat(repository.findByMalId("MAL-2022-9999")).isEmpty();
    }

    /* ---------------------------------------------------------------------- */
    /* Upsert and ecosystem filtering                                          */
    /* ---------------------------------------------------------------------- */

    /**
     * Deliberately <b>not</b> {@code @Transactional}, unlike its neighbours.
     *
     * <p>{@code JobRunner} calls {@code ingest} with no surrounding transaction, and the per-record
     * upsert is a self-invocation ({@code ingest} → {@code processRecord} → {@code upsert}, all on
     * one bean), so Spring's proxy never applies and its {@code @Transactional} is inert. A test that
     * wraps the whole thing in one transaction would hide exactly the failure that matters: on the
     * SECOND pass the existing row comes back with lazy {@code versions}/{@code ranges} collections,
     * and clearing them outside a session throws.
     *
     * <p>This is what makes {@code findForUpsert}'s fetch join load-bearing rather than an
     * optimisation.
     */
    @Test
    void reingestUpsertsInPlaceRatherThanDuplicating() throws IOException {
        Map<String, String> first = Map.of(
                "malicious-packages-main/osv/malicious/npm/upsert-pkg/MAL-2024-7.json",
                record("MAL-2024-7", "npm", "upsert-pkg", "first summary"));
        Map<String, String> second = Map.of(
                "malicious-packages-main/osv/malicious/npm/upsert-pkg/MAL-2024-7.json",
                record("MAL-2024-7", "npm", "upsert-pkg", "second summary"));

        github.expect(requestTo(ARCHIVE_URL)).andRespond(withSuccess(buildZip(first), zipType()));
        github.expect(requestTo(ARCHIVE_URL)).andRespond(withSuccess(buildZip(second), zipType()));

        ingestService.ingest(JobProgress.NOOP);
        assertThat(repository.findByMalId("MAL-2024-7")).hasSize(1);

        // A full refresh, not an incremental one: unlike the OSV mirror there is no per-record
        // high-water mark in a repository archive, so a second pass re-reads and overwrites.
        ingestService.ingest(JobProgress.NOOP);
        assertThat(repository.findByMalId("MAL-2024-7"))
                .as("the upsert key is (malId, ecosystem, packageName) — re-ingest must never duplicate")
                .hasSize(1);
        assertThat(mustFind("MAL-2024-7", "npm", "upsert-pkg").getSummary()).isEqualTo("second summary");

        github.verify();
    }

    @Test
    @Transactional
    void anEcosystemOutsideTheConfiguredListIsSkippedByPathBeforeItIsParsed() throws IOException {
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("malicious-packages-main/osv/malicious/npm/kept/MAL-2024-100.json",
                record("MAL-2024-100", "npm", "kept", "in a configured ecosystem"));
        // `vscode` is not in the test profile's secy.compromise.ecosystems.
        entries.put("malicious-packages-main/osv/malicious/vscode/skipped/MAL-2024-101.json",
                record("MAL-2024-101", "VSCode", "skipped", "in an unconfigured ecosystem"));

        github.expect(requestTo(ARCHIVE_URL)).andRespond(withSuccess(buildZip(entries), zipType()));

        IngestResult result = ingestService.ingest(JobProgress.NOOP);
        github.verify();

        assertThat(result.itemsProcessed()).isEqualTo(1);
        assertThat(repository.findByMalId("MAL-2024-100")).hasSize(1);
        assertThat(repository.findByMalId("MAL-2024-101")).isEmpty();
    }

    @Test
    @Transactional
    void aFlatArchiveWithNoEcosystemDirectoriesStillIngests() throws IOException {
        // Coded defensively: if OSSF ever publishes a GCS-style flat export, only the path
        // pre-filter goes idle — the record's own affected[].package.ecosystem still decides.
        github.expect(requestTo(ARCHIVE_URL)).andRespond(withSuccess(buildZip(Map.of(
                "MAL-2024-200.json", record("MAL-2024-200", "PyPI", "flat-pkg", "flat layout"))), zipType()));

        IngestResult result = ingestService.ingest(JobProgress.NOOP);
        github.verify();

        assertThat(result.itemsProcessed()).isEqualTo(1);
        assertThat(mustFind("MAL-2024-200", "PyPI", "flat-pkg").getSummary()).isEqualTo("flat layout");
    }

    /* ---------------------------------------------------------------------- */
    /* Fixtures                                                               */
    /* ---------------------------------------------------------------------- */

    private MaliciousPackage mustFind(String malId, String ecosystem, String packageName) {
        Optional<MaliciousPackage> found =
                repository.findByMalIdAndEcosystemAndPackageName(malId, ecosystem, packageName);
        assertThat(found).as("expected a row for (%s, %s, %s)", malId, ecosystem, packageName).isPresent();
        return found.get();
    }

    private static MediaType zipType() {
        return MediaType.parseMediaType("application/zip");
    }

    /** A minimal but structurally real record. */
    private static String record(String malId, String ecosystem, String name, String summary) {
        return """
                {
                  "id": "%s",
                  "modified": "2024-01-01T00:00:00Z",
                  "published": "2024-01-01T00:00:00Z",
                  "schema_version": "1.5.0",
                  "summary": "%s",
                  "affected": [
                    {
                      "package": {"ecosystem": "%s", "name": "%s"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
                    }
                  ]
                }
                """.formatted(malId, summary, ecosystem, name);
    }

    private static Map<String, String> fixture() {
        Map<String, String> entries = new LinkedHashMap<>();

        // Verbatim shape of a real PyPI record, trimmed.
        entries.put("malicious-packages-main/osv/malicious/pypi/beautiulsoup4/MAL-2023-1638.json", """
                {
                  "modified": "2023-08-21T20:12:58Z",
                  "published": "2023-02-10T12:45:05Z",
                  "schema_version": "1.5.0",
                  "id": "MAL-2023-1638",
                  "summary": "Malicious code in beautiulsoup4 (PyPI)",
                  "details": "Attacker distributed 900+ malicious packages via PyPI.",
                  "affected": [
                    {
                      "package": {"ecosystem": "PyPI", "name": "beautiulsoup4"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
                    }
                  ],
                  "credits": [{"name": "Checkmarx", "type": "FINDER"}],
                  "database_specific": {
                    "malicious-packages-origins": [
                      {
                        "source": "checkmarx",
                        "sha256": "1dcf1bf2779430822676c2a6c5cb352f7839ef8842f640c2be367cb2b7b7ec01",
                        "import_time": "2023-08-24T17:54:31.96126817Z",
                        "modified_time": "2023-08-21T20:12:58Z"
                      }
                    ]
                  }
                }
                """);

        // Enumerated versions[] alongside an introduced:"0" range, two packages, two origin sources.
        entries.put("malicious-packages-main/osv/malicious/npm/bucket-protocol-sdk-v2/MAL-2026-4502.json", """
                {
                  "id": "MAL-2026-4502",
                  "modified": "2026-08-18T00:30:28Z",
                  "published": "2026-05-20T04:04:00Z",
                  "schema_version": "1.6.0",
                  "summary": "Malicious code in bucket-protocol-sdk-v2 (npm)",
                  "details": "postinstall hook fetches and backgrounds an attacker binary.",
                  "aliases": ["GHSA-23pf-2cqf-xh64"],
                  "affected": [
                    {
                      "package": {
                        "name": "bucket-protocol-sdk-v2",
                        "ecosystem": "npm",
                        "purl": "pkg:npm/bucket-protocol-sdk-v2"
                      },
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                      "versions": ["1.0.26", "1.0.11"]
                    },
                    {
                      "package": {"name": "bucket-protocol-sdk-v3", "ecosystem": "npm"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
                    }
                  ],
                  "references": [
                    {"type": "PACKAGE", "url": "https://www.npmjs.com/package/bucket-protocol-sdk-v2/v/1.0.26"},
                    {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-23pf-2cqf-xh64"}
                  ],
                  "database_specific": {
                    "malicious-packages-origins": [
                      {
                        "source": "amazon-inspector",
                        "versions": ["1.0.26"],
                        "id": "IN-MAL-2026-003456",
                        "import_time": "2026-05-26T05:50:40.680023655Z",
                        "modified_time": "2026-05-20T04:04:30Z"
                      },
                      {
                        "source": "ghsa-malware",
                        "id": "IN-MAL-2026-003455",
                        "import_time": "2026-05-26T05:50:40.570388632Z",
                        "modified_time": "2026-05-20T04:04:10Z"
                      }
                    ]
                  }
                }
                """);

        // A genuinely bounded range — the case that must NOT read as "all versions".
        entries.put("malicious-packages-main/osv/malicious/npm/bounded-pkg/MAL-2024-0001.json", """
                {
                  "id": "MAL-2024-0001",
                  "modified": "2024-03-01T00:00:00Z",
                  "summary": "Malicious code in bounded-pkg (npm)",
                  "affected": [
                    {
                      "package": {"ecosystem": "npm", "name": "bounded-pkg"},
                      "ranges": [{"type": "SEMVER",
                                  "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.4"}]}]
                    }
                  ]
                }
                """);

        // Filed under osv/withdrawn/ and carrying no `withdrawn` field — the path alone must be
        // enough to take it out of matching.
        entries.put("malicious-packages-main/osv/withdrawn/npm/withdrawn-pkg/MAL-2022-0009.json", """
                {
                  "id": "MAL-2022-0009",
                  "modified": "2022-06-01T00:00:00Z",
                  "summary": "Retracted false positive",
                  "affected": [
                    {
                      "package": {"ecosystem": "npm", "name": "withdrawn-pkg"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
                    }
                  ]
                }
                """);

        // unmergable/ — no agreed package identity, so it is dropped rather than stored withdrawn.
        entries.put("malicious-packages-main/osv/unmergable/npm/unmergable-pkg/MAL-2022-9999.json", """
                {
                  "id": "MAL-2022-9999",
                  "modified": "2022-06-01T00:00:00Z",
                  "summary": "Unmergable report",
                  "affected": [
                    {
                      "package": {"ecosystem": "npm", "name": "unmergable-pkg"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
                    }
                  ]
                }
                """);

        // Not JSON, and the README that really does sit in osv/malicious/ — both must be ignored.
        entries.put("malicious-packages-main/osv/malicious/README.md", "# Malicious packages");

        return entries;
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
