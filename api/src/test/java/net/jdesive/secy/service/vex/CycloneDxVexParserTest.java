package net.jdesive.secy.service.vex;

import net.jdesive.secy.config.VexProperties;
import net.jdesive.secy.model.vex.ParsedVexDocument;
import net.jdesive.secy.model.vex.ParsedVexStatement;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexStatus;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Pure unit tests for the CycloneDX VEX shape, via {@link VexDocumentParser}. */
class CycloneDxVexParserTest {

    private final VexDocumentParser parser = new VexDocumentParser(new VexProperties());

    private ParsedVexDocument parse(String json) {
        return parser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void standaloneNotAffectedWithPkgRef() {
        ParsedVexDocument doc = parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
                  "version": 1,
                  "metadata": {"timestamp": "2026-01-01T00:00:00Z", "authors": [{"name": "Acme Vendor"}]},
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-7101",
                      "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_reachable",
                        "detail": "Not on the execution path."
                      },
                      "affects": [{"ref": "pkg:maven/acme/widget@1.0.0"}]
                    }
                  ]
                }
                """);

        assertThat(doc.format()).isEqualTo(VexDocumentFormat.CYCLONEDX);
        assertThat(doc.documentKey()).isEqualTo("urn:uuid:11111111-1111-1111-1111-111111111111");
        assertThat(doc.author()).isEqualTo("Acme Vendor");
        assertThat(doc.statements()).hasSize(1);

        ParsedVexStatement s = doc.statements().get(0);
        assertThat(s.cveId()).isEqualTo("CVE-2099-7101");
        assertThat(s.status()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(s.justification()).isEqualTo(VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH);
        assertThat(s.targetPurl()).isEqualTo("pkg:maven/acme/widget@1.0.0");
    }

    @Test
    void bomRefIsResolvedThroughTheComponentIndex() {
        ParsedVexDocument doc = parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
                  "components": [
                    {"bom-ref": "comp-1", "purl": "pkg:npm/leftpad@1.0.0"}
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-7102",
                      "analysis": {"state": "exploitable"},
                      "affects": [{"ref": "comp-1"}]
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(1);
        assertThat(doc.statements().get(0).targetPurl()).isEqualTo("pkg:npm/leftpad@1.0.0");
        assertThat(doc.statements().get(0).status()).isEqualTo(VexStatus.AFFECTED);
    }

    @Test
    void bomLinkUrnIsUrlDecodedAndResolved() {
        ParsedVexDocument doc = parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
                  "components": [
                    {"bom-ref": "comp/1", "purl": "pkg:npm/bomlink@1.0.0"}
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-7103",
                      "analysis": {"state": "in_triage"},
                      "affects": [{"ref": "urn:cdx:33333333-3333-3333-3333-333333333333/1#comp%2F1"}]
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(1);
        assertThat(doc.statements().get(0).targetPurl()).isEqualTo("pkg:npm/bomlink@1.0.0");
        assertThat(doc.statements().get(0).status()).isEqualTo(VexStatus.UNDER_INVESTIGATION);
    }

    @Test
    void everyAnalysisStateMaps() {
        record Case(String state, String expected) {
        }
        for (Case c : new Case[]{
                new Case("not_affected", "NOT_AFFECTED"),
                new Case("resolved", "FIXED"),
                new Case("resolved_with_pedigree", "FIXED"),
                new Case("exploitable", "AFFECTED"),
                new Case("in_triage", "UNDER_INVESTIGATION")}) {
            ParsedVexDocument doc = parse(oneVulnDoc(c.state()));
            assertThat(doc.statements()).as(c.state()).hasSize(1);
            assertThat(doc.statements().get(0).status().name()).isEqualTo(c.expected());
        }
    }

    @Test
    void falsePositiveMapsToNotAffectedWithDefaultSourceJustification() {
        ParsedVexDocument doc = parse(oneVulnDoc("false_positive"));
        ParsedVexStatement s = doc.statements().get(0);
        assertThat(s.status()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(s.sourceJustification()).isEqualTo("false_positive");
    }

    private static String oneVulnDoc(String state) {
        String justification = "not_affected".equals(state) ? ", \"justification\": \"code_not_present\"" : "";
        return """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:44444444-4444-4444-4444-444444444444",
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-7104",
                      "analysis": {"state": "%s"%s},
                      "affects": [{"ref": "pkg:npm/x@1.0.0"}]
                    }
                  ]
                }
                """.formatted(state, justification);
    }

    @Test
    void noAnalysisIsSkippedAsAVulnerabilityListingNotAnAssertion() {
        assertThrows(VexDocumentRejectedException.class, () -> parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:55555555-5555-5555-5555-555555555555",
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-7105",
                      "affects": [{"ref": "pkg:npm/x@1.0.0"}]
                    }
                  ]
                }
                """));
    }

    @Test
    void versionsArrayExactVersionEmitsPinnedStatement() {
        ParsedVexDocument doc = parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:66666666-6666-6666-6666-666666666666",
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-7106",
                      "analysis": {"state": "exploitable"},
                      "affects": [{
                        "ref": "pkg:npm/versioned@1.0.0",
                        "versions": [{"version": "1.0.0", "status": "affected"}]
                      }]
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(1);
        assertThat(doc.statements().get(0).matchVersion()).isEqualTo("1.0.0");
    }

    @Test
    void versionsArrayWithOnlyRangesOrUnaffectedSkipsTheWholeTarget() {
        assertThrows(VexDocumentRejectedException.class, () -> parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:77777777-7777-7777-7777-777777777777",
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-7107",
                      "analysis": {"state": "exploitable"},
                      "affects": [{
                        "ref": "pkg:npm/ranged@1.0.0",
                        "versions": [
                          {"range": "vers:npm/>=1.0.0|<2.0.0", "status": "affected"},
                          {"version": "0.9.0", "status": "unaffected"}
                        ]
                      }]
                    }
                  ]
                }
                """));
    }

    @Test
    void noVulnerabilitiesArrayIsRejectedNamingSbomUploadInstead() {
        VexDocumentRejectedException e = org.junit.jupiter.api.Assertions.assertThrows(
                VexDocumentRejectedException.class, () -> parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:88888888-8888-8888-8888-888888888888",
                  "components": []
                }
                """));
        assertThat(e.getMessage()).contains("POST /sbom");
    }

    @Test
    void specVersionBelow14IsRejected() {
        assertThrows(VexDocumentRejectedException.class, () -> parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.3",
                  "serialNumber": "urn:uuid:99999999-9999-9999-9999-999999999999",
                  "vulnerabilities": [{"id": "CVE-2099-7108", "analysis": {"state": "exploitable"}, "affects": [{"ref": "pkg:npm/x@1.0.0"}]}]
                }
                """));
    }

    @Test
    void unresolvableRefIsStoredUnmatchable() {
        ParsedVexDocument doc = parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-7109",
                      "analysis": {"state": "exploitable"},
                      "affects": [{"ref": "unknown-bom-ref"}]
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(1);
        assertThat(doc.statements().get(0).targetPurl()).isNull();
        assertThat(doc.warnings()).isNotEmpty();
    }

}
