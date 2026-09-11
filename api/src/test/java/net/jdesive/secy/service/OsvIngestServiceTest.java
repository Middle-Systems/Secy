package net.jdesive.secy.service;

import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.OsvEcosystemCursorRepository;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.OsvEcosystemCursor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The OSV ingest itself, with the GCS mirror stubbed at the transport (see
 * {@code KEVServiceIngestTest} for the pattern this follows) and its zip payload built in memory —
 * see {@code PHASE2-CONTRACT.md} §1 for the field-by-field contract this pins.
 */
@SpringBootTest
@TestPropertySource(properties = "secy.osv.ecosystems=npm")
class OsvIngestServiceTest {

    private static final String NPM_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

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

    /* ---------------------------------------------------------------------- */
    /* One pass over a zip covering every shape from the contract             */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void oneIngestPassPopulatesEveryShapeTheContractDescribes() throws IOException {
        gcs.expect(requestTo(NPM_URL)).andRespond(withSuccess(buildZip(fixtureRecords()), zipType()));

        IngestResult result = osvIngestService.ingest(JobProgress.NOOP);
        gcs.verify();

        assertThat(result.itemsProcessed()).isEqualTo(6);

        // Normal range advisory, with a real CVSS_V3 severity picked.
        OsvAdvisory normalRange = mustFind("GHSA-aaaa-normal-range", "npm", "left-pad");
        assertThat(normalRange.getRanges()).hasSize(1);
        OsvAffectedRange range = normalRange.getRanges().get(0);
        assertThat(range.getIntroduced()).isEqualTo("1.0.0");
        assertThat(range.getFixed()).isEqualTo("1.2.0");
        assertThat(range.getLastAffected()).isNull();
        assertThat(normalRange.getSeverity()).isEqualTo("CRITICAL");
        assertThat(normalRange.getCvssVector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assertThat(normalRange.getAliases()).contains("CVE-2021-0001", "GHSA-aaaa-normal-range");

        // Enumerated versions[].
        OsvAdvisory enumerated = mustFind("GHSA-bbbb-versions", "npm", "enum-pkg");
        assertThat(enumerated.getVersions()).containsExactlyInAnyOrder("2.0.0", "2.0.1");

        // Withdrawn — stored, not deleted.
        OsvAdvisory withdrawn = mustFind("GHSA-cccc-withdrawn", "npm", "with-pkg");
        assertThat(withdrawn.isCurrent()).isFalse();
        assertThat(withdrawn.getWithdrawn()).isNotNull();

        // The record's own id is a CVE and aliases[] is empty — contract §1.2.
        OsvAdvisory cveIsId = mustFind("CVE-2021-0004", "npm", "cve-id-pkg");
        assertThat(cveIsId.getAliases()).containsExactly("CVE-2021-0004");
        assertThat(cveIsId.cveAlias()).isEqualTo("CVE-2021-0004");

        // One record, two packages -> two rows, both resolvable by osvId.
        List<OsvAdvisory> multi = osvAdvisoryRepository.findByOsvId("GHSA-dddd-multi");
        assertThat(multi).hasSize(2);
        assertThat(multi).extracting(OsvAdvisory::getPackageName).containsExactlyInAnyOrder("multi-a", "multi-b");

        // The contract's own two-interval flattening example.
        OsvAdvisory twoRanges = mustFind("GHSA-eeee-tworanges", "npm", "two-range-pkg");
        assertThat(twoRanges.getRanges()).hasSize(2);
        assertThat(twoRanges.getRanges())
                .extracting(OsvAffectedRange::getIntroduced, OsvAffectedRange::getFixed)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("1.0", "1.2"),
                        org.assertj.core.groups.Tuple.tuple("2.0", "2.1"));

        // Cursor advanced to the newest `modified` seen this run.
        OsvEcosystemCursor cursor = cursorRepository.findById("npm").orElseThrow();
        assertThat(cursor.getLastModified()).isEqualTo(LocalDateTime.of(2024, 1, 1, 0, 0));
        assertThat(cursor.getLastIngestedAt()).isNotNull();
    }

    /* ---------------------------------------------------------------------- */
    /* Upsert, skip-on-stale-modified, and cursor advancement                 */
    /* ---------------------------------------------------------------------- */

    @Test
    @Transactional
    void reingestUpsertsInPlaceSkipsStaleModifiedAndAdvancesTheCursor() throws IOException {
        String recordV1 = upsertRecord("2024-01-01T00:00:00Z", "first");
        String recordV2SameModified = upsertRecord("2024-01-01T00:00:00Z", "second");
        String recordV3NewerModified = upsertRecord("2024-06-01T00:00:00Z", "third");

        gcs.expect(requestTo(NPM_URL))
                .andRespond(withSuccess(buildZip(Map.of("a.json", recordV1)), zipType()));
        gcs.expect(requestTo(NPM_URL))
                .andRespond(withSuccess(buildZip(Map.of("a.json", recordV2SameModified)), zipType()));
        gcs.expect(requestTo(NPM_URL))
                .andRespond(withSuccess(buildZip(Map.of("a.json", recordV3NewerModified)), zipType()));

        // Run 1: fresh insert.
        osvIngestService.ingest(JobProgress.NOOP);
        assertThat(osvAdvisoryRepository.findByOsvId("GHSA-upsert-test")).hasSize(1);
        assertThat(mustFind("GHSA-upsert-test", "npm", "upsert-pkg").getSummary()).isEqualTo("first");
        assertThat(cursorRepository.findById("npm").orElseThrow().getLastModified())
                .isEqualTo(LocalDateTime.of(2024, 1, 1, 0, 0));

        // Run 2: same `modified` as the cursor — not strictly newer, so it must be skipped.
        osvIngestService.ingest(JobProgress.NOOP);
        assertThat(osvAdvisoryRepository.findByOsvId("GHSA-upsert-test")).hasSize(1);
        assertThat(mustFind("GHSA-upsert-test", "npm", "upsert-pkg").getSummary())
                .as("a record no newer than the cursor must not overwrite the stored row")
                .isEqualTo("first");

        // Run 3: strictly newer `modified` — updates the same row in place, cursor advances.
        osvIngestService.ingest(JobProgress.NOOP);
        assertThat(osvAdvisoryRepository.findByOsvId("GHSA-upsert-test"))
                .as("the upsert key is (osvId, ecosystem, packageName) — re-ingest must never duplicate")
                .hasSize(1);
        assertThat(mustFind("GHSA-upsert-test", "npm", "upsert-pkg").getSummary()).isEqualTo("third");
        assertThat(cursorRepository.findById("npm").orElseThrow().getLastModified())
                .isEqualTo(LocalDateTime.of(2024, 6, 1, 0, 0));

        gcs.verify();
    }

    /* ---------------------------------------------------------------------- */
    /* Failure semantics                                                      */
    /* ---------------------------------------------------------------------- */

    @Test
    void aFailedPullLeavesTheCursorExactlyWhereItWas() {
        OsvEcosystemCursor existing = new OsvEcosystemCursor();
        existing.setEcosystem("npm");
        existing.setLastModified(LocalDateTime.of(2023, 1, 1, 0, 0));
        existing.setLastIngestedAt(LocalDateTime.of(2023, 1, 1, 0, 0));
        cursorRepository.save(existing);

        gcs.expect(requestTo(NPM_URL)).andRespond(withServerError());

        assertThatThrownBy(() -> osvIngestService.ingest(JobProgress.NOOP))
                .isInstanceOf(IllegalStateException.class);

        OsvEcosystemCursor unchanged = cursorRepository.findById("npm").orElseThrow();
        assertThat(unchanged.getLastModified()).isEqualTo(LocalDateTime.of(2023, 1, 1, 0, 0));
        assertThat(unchanged.getLastIngestedAt()).isEqualTo(LocalDateTime.of(2023, 1, 1, 0, 0));
    }

    /* ---------------------------------------------------------------------- */
    /* Fixtures                                                               */
    /* ---------------------------------------------------------------------- */

    private OsvAdvisory mustFind(String osvId, String ecosystem, String packageName) {
        Optional<OsvAdvisory> found =
                osvAdvisoryRepository.findByOsvIdAndEcosystemAndPackageName(osvId, ecosystem, packageName);
        assertThat(found).as("expected a row for (%s, %s, %s)", osvId, ecosystem, packageName).isPresent();
        return found.get();
    }

    private static MediaType zipType() {
        return MediaType.parseMediaType("application/zip");
    }

    private static Map<String, String> fixtureRecords() {
        Map<String, String> records = new LinkedHashMap<>();

        records.put("normal-range.json", """
                {
                  "id": "GHSA-aaaa-normal-range",
                  "modified": "2024-01-01T00:00:00Z",
                  "published": "2023-12-01T00:00:00Z",
                  "aliases": ["CVE-2021-0001"],
                  "summary": "Normal range advisory",
                  "details": "Details for the normal range advisory",
                  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                  "affected": [
                    {
                      "package": {"ecosystem": "npm", "name": "left-pad", "purl": "pkg:npm/left-pad"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}]
                    }
                  ],
                  "references": [{"type": "ADVISORY", "url": "https://example.com/ghsa-aaaa"}]
                }
                """);

        records.put("versions.json", """
                {
                  "id": "GHSA-bbbb-versions",
                  "modified": "2024-01-01T00:00:00Z",
                  "aliases": ["CVE-2021-0002"],
                  "summary": "Enumerated versions advisory",
                  "affected": [
                    {"package": {"ecosystem": "npm", "name": "enum-pkg"}, "versions": ["2.0.0", "2.0.1"]}
                  ]
                }
                """);

        records.put("withdrawn.json", """
                {
                  "id": "GHSA-cccc-withdrawn",
                  "modified": "2024-01-01T00:00:00Z",
                  "withdrawn": "2024-06-01T00:00:00Z",
                  "aliases": ["CVE-2021-0003"],
                  "summary": "Withdrawn advisory",
                  "affected": [
                    {
                      "package": {"ecosystem": "npm", "name": "with-pkg"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]
                    }
                  ]
                }
                """);

        records.put("cve-is-id.json", """
                {
                  "id": "CVE-2021-0004",
                  "modified": "2024-01-01T00:00:00Z",
                  "aliases": [],
                  "summary": "The record's own id is the CVE, aliases[] is empty",
                  "affected": [
                    {"package": {"ecosystem": "npm", "name": "cve-id-pkg"}, "versions": ["3.0.0"]}
                  ]
                }
                """);

        records.put("multi-package.json", """
                {
                  "id": "GHSA-dddd-multi",
                  "modified": "2024-01-01T00:00:00Z",
                  "aliases": ["CVE-2021-0005"],
                  "summary": "One record naming two packages",
                  "affected": [
                    {"package": {"ecosystem": "npm", "name": "multi-a"}, "versions": ["1.0.0"]},
                    {"package": {"ecosystem": "npm", "name": "multi-b"}, "versions": ["1.0.0"]}
                  ]
                }
                """);

        records.put("two-ranges.json", """
                {
                  "id": "GHSA-eeee-tworanges",
                  "modified": "2024-01-01T00:00:00Z",
                  "aliases": ["CVE-2021-0006"],
                  "summary": "One ranges[] entry, two disjoint intervals",
                  "affected": [
                    {
                      "package": {"ecosystem": "npm", "name": "two-range-pkg"},
                      "ranges": [{"type": "SEMVER", "events": [
                        {"introduced": "1.0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"fixed": "2.1"}
                      ]}]
                    }
                  ]
                }
                """);

        return records;
    }

    private static String upsertRecord(String modified, String summary) {
        return """
                {
                  "id": "GHSA-upsert-test",
                  "modified": "%s",
                  "aliases": ["CVE-2021-0099"],
                  "summary": "%s",
                  "affected": [
                    {"package": {"ecosystem": "npm", "name": "upsert-pkg"}, "versions": ["1.0.0"]}
                  ]
                }
                """.formatted(modified, summary);
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
