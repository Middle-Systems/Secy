package net.jdesive.secy.service.sbom;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M1h (ROADMAP.md — "M1h — SBOM quality scoring"): the new supplier/author/timestamp/dependency
 * parsing that feeds {@code SbomQualityScorer}, exercised through the real {@link SbomParser} and
 * normalizers — same "no Spring context" reasoning as {@code SecondaryIdentifierParsingTest}.
 */
class SbomQualityParsingTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SbomParser parser =
            new SbomParser(new ObjectMapper(), new CycloneDXNormalizer(), new SpdxNormalizer());

    /* ------------------------------------------------------------------ */
    /* CycloneDX — supplier                                                */
    /* ------------------------------------------------------------------ */

    @Test
    void cycloneDxComponentSupplierNameIsParsed() throws Exception {
        NormalizedComponent c = only(parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [
                    { "type": "library", "name": "a", "version": "1.0", "supplier": { "name": "Acme" } }
                  ] }
                """));
        assertThat(c.supplier()).isEqualTo("Acme");
    }

    @Test
    void cycloneDxSupplierAsStringOrArrayOrNoNameObjectIsNullNotAnException() throws Exception {
        NormalizedComponent stringSupplier = only(parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "name": "a", "supplier": "Acme" } ] }
                """));
        assertThat(stringSupplier.supplier()).isNull();

        NormalizedComponent arraySupplier = only(parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "name": "a", "supplier": ["Acme"] } ] }
                """));
        assertThat(arraySupplier.supplier()).isNull();

        NormalizedComponent noNameObject = only(parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "name": "a", "supplier": { "url": ["https://acme.example"] } } ] }
                """));
        assertThat(noNameObject.supplier()).isNull();
    }

    /* ------------------------------------------------------------------ */
    /* CycloneDX — authors / manufacturer                                  */
    /* ------------------------------------------------------------------ */

    @Test
    void cycloneDxAuthorsNameWithEmailFallback() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": {
                    "authors": [ { "name": "Jane Doe" }, { "email": "team@acme.example" } ]
                  },
                  "components": [ { "type": "library", "name": "a" } ] }
                """);
        assertThat(doc.authors()).containsExactly("Jane Doe", "team@acme.example");
    }

    @Test
    void malformedAuthorsObjectNotArrayIsEmptyNotAnException() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "authors": { "name": "not-an-array" } },
                  "components": [ { "type": "library", "name": "a" } ] }
                """);
        assertThat(doc.authors()).isEmpty();
    }

    @Test
    void cycloneDx16ManufacturerNameCountsAsAuthorButOnlyOnA16Document() throws Exception {
        NormalizedSbom doc16 = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                  "metadata": { "manufacturer": { "name": "Acme Build Team" } },
                  "components": [ { "type": "library", "name": "a" } ] }
                """);
        assertThat(doc16.authors()).containsExactly("Acme Build Team");

        // 1.5's metadata.manufacture (singular, describes the component, not the SBOM) is a
        // different field entirely and is never bound here — this document declares no manufacturer
        // at all, so authors stays empty regardless of specVersion.
        NormalizedSbom doc15 = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "manufacture": { "name": "Acme Build Team" } },
                  "components": [ { "type": "library", "name": "a" } ] }
                """);
        assertThat(doc15.authors()).isEmpty();
    }

    /* ------------------------------------------------------------------ */
    /* CycloneDX — timestamp                                               */
    /* ------------------------------------------------------------------ */

    @Test
    void cycloneDxMetadataTimestampIsParsed() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "timestamp": "2026-09-20T10:00:00Z" },
                  "components": [ { "type": "library", "name": "a" } ] }
                """);
        assertThat(doc.documentTimestamp()).isNotNull();
    }

    @Test
    void noMetadataTimestampIsNull() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "name": "a" } ] }
                """);
        assertThat(doc.documentTimestamp()).isNull();
    }

    /* ------------------------------------------------------------------ */
    /* CycloneDX — dependencies                                            */
    /* ------------------------------------------------------------------ */

    @Test
    void cycloneDxDependenciesRefAndDependsOnPopulateTheSetIncludingAnEmptyDependsOnLeaf() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [
                    { "type": "library", "bom-ref": "root", "name": "root" },
                    { "type": "library", "bom-ref": "leaf", "name": "leaf" }
                  ],
                  "dependencies": [
                    { "ref": "root", "dependsOn": [ "leaf" ] },
                    { "ref": "leaf", "dependsOn": [] }
                  ] }
                """);
        assertThat(doc.dependencyRelationshipRefs()).containsExactlyInAnyOrder("root", "leaf");
    }

    @Test
    void malformedDependenciesStringNotArrayIsEmptyNotAnException() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "bom-ref": "root", "name": "root" } ],
                  "dependencies": "not-an-array" }
                """);
        assertThat(doc.dependencyRelationshipRefs()).isEmpty();
    }

    /* ------------------------------------------------------------------ */
    /* SPDX — supplier                                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void spdxSupplierPrefixIsStripped() throws Exception {
        NormalizedComponent org = byNameSpdx(parseSpdx(spdxWithPackage("""
                { "SPDXID": "SPDXRef-Package-a", "name": "a", "versionInfo": "1.0", "supplier": "Organization: Acme" }
                """)), "a");
        assertThat(org.supplier()).isEqualTo("Acme");

        NormalizedComponent person = byNameSpdx(parseSpdx(spdxWithPackage("""
                { "SPDXID": "SPDXRef-Package-b", "name": "b", "versionInfo": "1.0", "supplier": "Person: Jane" }
                """)), "b");
        assertThat(person.supplier()).isEqualTo("Jane");

        NormalizedComponent none = byNameSpdx(parseSpdx(spdxWithPackage("""
                { "SPDXID": "SPDXRef-Package-c", "name": "c", "versionInfo": "1.0", "supplier": "NOASSERTION" }
                """)), "c");
        assertThat(none.supplier()).isNull();
    }

    /* ------------------------------------------------------------------ */
    /* SPDX — authors (creators)                                           */
    /* ------------------------------------------------------------------ */

    @Test
    void spdxPersonAndOrganizationCreatorsBecomeAuthorsToolDoesNot() throws Exception {
        NormalizedSbom doc = parseSpdx("""
                { "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "d",
                  "creationInfo": { "creators": [ "Tool: syft-0.98.0", "Organization: Acme", "Person: Jane" ] },
                  "documentDescribes": [ "SPDXRef-Package-root" ],
                  "packages": [
                    { "SPDXID": "SPDXRef-Package-root", "name": "root", "versionInfo": "1.0" }
                  ],
                  "relationships": [
                    { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-root" }
                  ] }
                """);
        assertThat(doc.authors()).containsExactlyInAnyOrder("Acme", "Jane");
    }

    /* ------------------------------------------------------------------ */
    /* SPDX — timestamp                                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void spdxCreatedIsParsedAndAnUnparseableValueIsNullNotAnException() throws Exception {
        NormalizedSbom good = parseSpdx(spdxWithCreated("2026-09-20T10:00:00Z"));
        // Converted to system-default-zone LocalDateTime (same instant, not necessarily the same
        // wall-clock hour as the UTC input) — same conversion CycloneDXNormalizer/VexParsing use.
        LocalDateTime expected = java.time.OffsetDateTime.parse("2026-09-20T10:00:00Z")
                .atZoneSameInstant(java.time.ZoneId.systemDefault()).toLocalDateTime();
        assertThat(good.documentTimestamp()).isEqualTo(expected);

        NormalizedSbom bad = parseSpdx(spdxWithCreated("not-a-date"));
        assertThat(bad.documentTimestamp()).isNull();
    }

    /* ------------------------------------------------------------------ */
    /* SPDX — dependency relationships                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void spdxDependsOnAndContainsAddBothEndsDescribesDoesNot() throws Exception {
        NormalizedSbom doc = parseSpdx("""
                { "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "d",
                  "creationInfo": { "creators": [ "Tool: syft" ] },
                  "documentDescribes": [ "SPDXRef-Package-root" ],
                  "packages": [
                    { "SPDXID": "SPDXRef-Package-root", "name": "root", "versionInfo": "1.0" },
                    { "SPDXID": "SPDXRef-Package-a", "name": "a", "versionInfo": "1.0" },
                    { "SPDXID": "SPDXRef-Package-b", "name": "b", "versionInfo": "1.0" }
                  ],
                  "relationships": [
                    { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-root" },
                    { "spdxElementId": "SPDXRef-Package-root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-a" },
                    { "spdxElementId": "SPDXRef-Package-root", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-b" }
                  ] }
                """);
        assertThat(doc.dependencyRelationshipRefs()).containsExactlyInAnyOrder(
                "SPDXRef-Package-root", "SPDXRef-Package-a", "SPDXRef-Package-b");
        assertThat(doc.dependencyRelationshipRefs()).doesNotContain("SPDXRef-DOCUMENT");
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private NormalizedSbom parse(String json) throws Exception {
        return parser.parse(mapper.readTree(json));
    }

    private NormalizedSbom parseSpdx(String json) throws Exception {
        return parser.parse(mapper.readTree(json));
    }

    private static NormalizedComponent only(NormalizedSbom doc) {
        assertThat(doc.components()).hasSize(1);
        return doc.components().get(0);
    }

    private static NormalizedComponent byNameSpdx(NormalizedSbom doc, String name) {
        return doc.components().stream().filter(c -> name.equals(c.name())).findFirst()
                .orElseThrow(() -> new AssertionError("No component named " + name));
    }

    private static String spdxWithPackage(String packageJson) {
        return """
                { "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "d",
                  "creationInfo": { "creators": [ "Tool: syft" ] },
                  "documentDescribes": [ "SPDXRef-Package-root" ],
                  "packages": [
                    { "SPDXID": "SPDXRef-Package-root", "name": "root", "versionInfo": "1.0" },
                    %s
                  ],
                  "relationships": [
                    { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-root" }
                  ] }
                """.formatted(packageJson);
    }

    private static String spdxWithCreated(String created) {
        return """
                { "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "d",
                  "creationInfo": { "created": "%s", "creators": [ "Tool: syft" ] },
                  "documentDescribes": [ "SPDXRef-Package-root" ],
                  "packages": [
                    { "SPDXID": "SPDXRef-Package-root", "name": "root", "versionInfo": "1.0" }
                  ],
                  "relationships": [
                    { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-root" }
                  ] }
                """.formatted(created);
    }

}
