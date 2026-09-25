package net.jdesive.secy.service.vex;

import net.jdesive.secy.config.VexProperties;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Every document-shape rejection {@link VexDocumentParser} is responsible for, with precise
 * messages — the "which of the three formats, or none" decision, and the shared hardening limits
 * (nesting depth, duplicate keys, statement count, zero usable statements).
 */
class VexFormatDetectionTest {

    private ParsedRejection parse(VexDocumentParser parser, String json) {
        VexDocumentRejectedException e = assertThrows(VexDocumentRejectedException.class,
                () -> parser.parse(json.getBytes(StandardCharsets.UTF_8)));
        return new ParsedRejection(e.getMessage());
    }

    private record ParsedRejection(String message) {
    }

    private final VexDocumentParser parser = new VexDocumentParser(new VexProperties());

    @Test
    void nonObjectRootIsRejected() {
        var r = parse(parser, "[1, 2, 3]");
        assertThat(r.message()).contains("must be a JSON object");
    }

    @Test
    void spdxDocumentFallsThroughToUnrecognisedShape() {
        var r = parse(parser, """
                {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": []}
                """);
        assertThat(r.message()).contains("Unrecognised document shape");
    }

    @Test
    void cycloneDxWithNoVulnerabilitiesIsRejectedNamingSbomUpload() {
        var r = parse(parser, """
                {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
                """);
        assertThat(r.message()).contains("POST /sbom");
    }

    @Test
    void cycloneDxBelowMinimumSpecVersionIsRejected() {
        var r = parse(parser, """
                {"bomFormat": "CycloneDX", "specVersion": "1.2", "vulnerabilities": [{"id": "CVE-2099-7301"}]}
                """);
        assertThat(r.message()).contains("1.4");
    }

    @Test
    void csaf21IsRejected() {
        var r = parse(parser, """
                {"document": {"csaf_version": "2.1", "category": "csaf_vex"}}
                """);
        assertThat(r.message()).contains("2.0");
    }

    @Test
    void csafBaseCategoryIsRejected() {
        var r = parse(parser, """
                {"document": {"csaf_version": "2.0", "category": "csaf_base"}}
                """);
        assertThat(r.message()).contains("category");
    }

    @Test
    void openVexNonArrayStatementsIsRejected() {
        var r = parse(parser, """
                {"@context": "https://openvex.dev/ns/v0.2.0", "statements": {}}
                """);
        assertThat(r.message()).contains("statements");
    }

    @Test
    void invalidJsonIsRejected() {
        var r = parse(parser, "{not valid json");
        assertThat(r.message()).contains("not valid JSON");
    }

    @Test
    void truncatedJsonIsRejected() {
        var r = parse(parser, """
                {"@context": "https://openvex.dev/ns/v0.2.0", "statements":
                """);
        assertThat(r.message()).contains("not valid JSON");
    }

    @Test
    void trailingGarbageAfterAValidDocumentIsRejected() {
        var r = parse(parser, """
                {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}garbage
                """);
        assertThat(r.message()).contains("not valid JSON");
    }

    @Test
    void duplicateKeysAreRejected() {
        var r = parse(parser, """
                {"@context": "https://openvex.dev/ns/v0.2.0", "@context": "https://openvex.dev/ns/v0.2.0", "statements": []}
                """);
        assertThat(r.message()).contains("not valid JSON");
    }

    @Test
    void nestingDepthOverTheLimitIsRejected() {
        VexProperties props = new VexProperties();
        props.setMaxNestingDepth(4);
        VexDocumentParser shallow = new VexDocumentParser(props);
        StringBuilder nested = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            nested.append("{\"a\":");
        }
        nested.append("1");
        nested.append("}".repeat(20));
        VexDocumentRejectedException e = assertThrows(VexDocumentRejectedException.class,
                () -> shallow.parse(nested.toString().getBytes(StandardCharsets.UTF_8)));
        assertThat(e.getMessage()).contains("not valid JSON");
    }

    @Test
    void zeroUsableStatementsIsRejected() {
        var r = parse(parser, """
                {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "x", "statements": []}
                """);
        assertThat(r.message()).contains("no usable VEX statements");
    }

    @Test
    void tooManyStatementsIsRejected() {
        VexProperties props = new VexProperties();
        props.setMaxStatements(2);
        VexDocumentParser limited = new VexDocumentParser(props);
        StringBuilder statements = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            if (i > 0) {
                statements.append(",");
            }
            statements.append("""
                    {"vulnerability": {"name": "CVE-2099-73%02d"}, "products": [{"@id": "pkg:npm/x%d@1.0.0"}], "status": "affected"}
                    """.formatted(i, i));
        }
        String json = """
                {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "x", "statements": [%s]}
                """.formatted(statements);
        VexDocumentRejectedException e = assertThrows(VexDocumentRejectedException.class,
                () -> limited.parse(json.getBytes(StandardCharsets.UTF_8)));
        assertThat(e.getMessage()).contains("limit");
    }

}
