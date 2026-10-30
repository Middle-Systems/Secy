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

/** Pure unit tests for the OpenVEX shape, via {@link VexDocumentParser} (the only real entry point). */
class OpenVexParserTest {

    private final VexDocumentParser parser = new VexDocumentParser(new VexProperties());

    private ParsedVexDocument parse(String json) {
        return parser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void v020NotAffectedWithJustificationAndImpactStatement() {
        ParsedVexDocument doc = parse("""
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://acme.example/vex/1",
                  "author": "Acme Product Security",
                  "version": 1,
                  "last_updated": "2026-01-01T00:00:00Z",
                  "statements": [
                    {
                      "vulnerability": {"name": "CVE-2099-7001"},
                      "products": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
                      "status": "not_affected",
                      "justification": "vulnerable_code_not_in_execute_path",
                      "impact_statement": "JndiLookup is stripped at build time."
                    }
                  ]
                }
                """);

        assertThat(doc.format()).isEqualTo(VexDocumentFormat.OPENVEX);
        assertThat(doc.specVersion()).isEqualTo("v0.2.0");
        assertThat(doc.documentKey()).isEqualTo("https://acme.example/vex/1");
        assertThat(doc.author()).isEqualTo("Acme Product Security");
        assertThat(doc.statements()).hasSize(1);

        ParsedVexStatement s = doc.statements().get(0);
        assertThat(s.cveId()).isEqualTo("CVE-2099-7001");
        assertThat(s.status()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(s.justification()).isEqualTo(VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH);
        assertThat(s.sourceJustification()).isEqualTo("vulnerable_code_not_in_execute_path");
        assertThat(s.impactStatement()).contains("JndiLookup");
        assertThat(s.targetPurl()).isEqualTo("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
    }

    @Test
    void legacy001BareContextAndStringShapedFields() {
        ParsedVexDocument doc = parse("""
                {
                  "@context": "https://openvex.dev/ns",
                  "@id": "https://acme.example/vex/legacy",
                  "author": "Acme",
                  "statements": [
                    {
                      "vulnerability": "CVE-2099-7002",
                      "products": ["pkg:npm/leftpad@1.0.0"],
                      "status": "affected"
                    }
                  ]
                }
                """);

        assertThat(doc.specVersion()).isEqualTo("0.0.1");
        assertThat(doc.statements()).hasSize(1);
        ParsedVexStatement s = doc.statements().get(0);
        assertThat(s.cveId()).isEqualTo("CVE-2099-7002");
        assertThat(s.status()).isEqualTo(VexStatus.AFFECTED);
        assertThat(s.targetPurl()).isEqualTo("pkg:npm/leftpad@1.0.0");
    }

    @Test
    void everyStatusValueMaps() {
        for (var pair : new String[][]{
                {"not_affected", "NOT_AFFECTED"},
                {"affected", "AFFECTED"},
                {"fixed", "FIXED"},
                {"under_investigation", "UNDER_INVESTIGATION"}}) {
            ParsedVexDocument doc = parse(oneStatementDoc(pair[0]));
            assertThat(doc.statements()).as(pair[0]).hasSize(1);
            assertThat(doc.statements().get(0).status().name()).isEqualTo(pair[1]);
        }
    }

    private static String oneStatementDoc(String status) {
        String justification = "not_affected".equals(status) ? "\"justification\": \"component_not_present\"," : "";
        return """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://acme.example/vex/status",
                  "statements": [
                    {
                      "vulnerability": {"name": "CVE-2099-7003"},
                      "products": [{"@id": "pkg:npm/x@1.0.0"}],
                      %s
                      "status": "%s"
                    }
                  ]
                }
                """.formatted(justification, status);
    }

    @Test
    void unrecognisedStatusIsSkippedWithAWarning() {
        assertRejectedAsEmpty(() -> parse("""
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://acme.example/vex/bad-status",
                  "statements": [
                    {
                      "vulnerability": {"name": "CVE-2099-7004"},
                      "products": [{"@id": "pkg:npm/x@1.0.0"}],
                      "status": "nonsense"
                    }
                  ]
                }
                """));
    }

    @Test
    void reasonlessNotAffectedIsSkipped() {
        assertRejectedAsEmpty(() -> parse("""
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://acme.example/vex/reasonless",
                  "statements": [
                    {
                      "vulnerability": {"name": "CVE-2099-7005"},
                      "products": [{"@id": "pkg:npm/x@1.0.0"}],
                      "status": "not_affected"
                    }
                  ]
                }
                """));
    }

    @Test
    void subcomponentsProduceOneTargetEach() {
        ParsedVexDocument doc = parse("""
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://acme.example/vex/subs",
                  "statements": [
                    {
                      "vulnerability": {"name": "CVE-2099-7006"},
                      "products": [
                        {
                          "@id": "pkg:oci/acme-image@1.0",
                          "subcomponents": [
                            {"@id": "pkg:npm/subpkg-a@1.0.0"},
                            {"@id": "pkg:npm/subpkg-b@1.0.0"}
                          ]
                        }
                      ],
                      "status": "affected"
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(2);
        assertThat(doc.statements()).extracting(ParsedVexStatement::targetPurl)
                .containsExactlyInAnyOrder("pkg:npm/subpkg-a@1.0.0", "pkg:npm/subpkg-b@1.0.0");
        assertThat(doc.statements()).allSatisfy(s -> assertThat(s.productRef()).contains(">"));
    }

    @Test
    void productWithNoUsablePurlIsStoredUnmatchableNotDropped() {
        ParsedVexDocument doc = parse("""
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://acme.example/vex/nopurl",
                  "statements": [
                    {
                      "vulnerability": {"name": "CVE-2099-7007"},
                      "products": [{"@id": "acme:some-non-purl-id"}],
                      "status": "affected"
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(1);
        assertThat(doc.statements().get(0).targetPurl()).isNull();
        assertThat(doc.warnings()).anyMatch(w -> w.contains("no usable PURL"));
    }

    @Test
    void multipleCveAliasesEmitOneStatementPerDistinctCve() {
        ParsedVexDocument doc = parse("""
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://acme.example/vex/aliases",
                  "statements": [
                    {
                      "vulnerability": {"name": "CVE-2099-7008", "aliases": ["CVE-2099-7009"]},
                      "products": [{"@id": "pkg:npm/x@1.0.0"}],
                      "status": "affected"
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).extracting(ParsedVexStatement::cveId)
                .containsExactlyInAnyOrder("CVE-2099-7008", "CVE-2099-7009");
    }

    @Test
    void nonArrayStatementsIsRejected() {
        org.junit.jupiter.api.Assertions.assertThrows(VexDocumentRejectedException.class, () -> parse("""
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://acme.example/vex/bad",
                  "statements": "not-an-array"
                }
                """));
    }

    /** Helper: every "skip everything" fixture above ends up with zero usable statements -> rejected. */
    private static void assertRejectedAsEmpty(Runnable action) {
        org.junit.jupiter.api.Assertions.assertThrows(VexDocumentRejectedException.class, action::run);
    }

}
