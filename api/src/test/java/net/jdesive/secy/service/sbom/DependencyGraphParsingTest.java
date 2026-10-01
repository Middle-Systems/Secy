package net.jdesive.secy.service.sbom;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.component.DependencyEdge;
import net.jdesive.secy.model.component.NormalizedSbom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M1l (ROADMAP.md — "Dependency graph preserved"): the directed edge list and root-ref extraction
 * that feeds {@code DependencyGraphAnalyzer}, exercised through the real {@link SbomParser} and
 * normalizers — same "no Spring context" reasoning as {@code SbomQualityParsingTest}. Also pins
 * that {@code dependencyRelationshipRefs()} (the M1h presence set) is completely unaffected by any
 * of this.
 */
class DependencyGraphParsingTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SbomParser parser =
            new SbomParser(new ObjectMapper(), new CycloneDXNormalizer(), new SpdxNormalizer());

    /* ------------------------------------------------------------------ */
    /* CycloneDX                                                           */
    /* ------------------------------------------------------------------ */

    @Test
    void cycloneDxRootToAToBGivesEdgesInOrderWithCorrectRootRefs() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "component": { "type": "application", "bom-ref": "root", "name": "root" } },
                  "components": [
                    { "type": "library", "bom-ref": "a", "name": "a" },
                    { "type": "library", "bom-ref": "b", "name": "b" }
                  ],
                  "dependencies": [
                    { "ref": "root", "dependsOn": [ "a" ] },
                    { "ref": "a", "dependsOn": [ "b" ] }
                  ] }
                """);
        assertThat(doc.dependencyEdges()).containsExactly(
                new DependencyEdge("root", "a"), new DependencyEdge("a", "b"));
        assertThat(doc.dependencyRootRefs()).containsExactly("root");
    }

    @Test
    void emptyDependsOnGivesNoEdgeButStillCountsInThePresenceSet() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "bom-ref": "x", "name": "x" } ],
                  "dependencies": [ { "ref": "x", "dependsOn": [] } ] }
                """);
        assertThat(doc.dependencyEdges()).isEmpty();
        assertThat(doc.dependencyRelationshipRefs()).containsExactly("x");
    }

    @Test
    void duplicateDependsOnIsDedupedAndSelfLoopIsDropped() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [
                    { "type": "library", "bom-ref": "a", "name": "a" },
                    { "type": "library", "bom-ref": "b", "name": "b" }
                  ],
                  "dependencies": [
                    { "ref": "a", "dependsOn": [ "b", "b" ] },
                    { "ref": "b", "dependsOn": [ "b" ] }
                  ] }
                """);
        assertThat(doc.dependencyEdges()).containsExactly(new DependencyEdge("a", "b"));
    }

    @Test
    void malformedDependenciesNeverThrow() throws Exception {
        NormalizedSbom stringShape = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "bom-ref": "a", "name": "a" } ],
                  "dependencies": "not-an-array" }
                """);
        assertThat(stringShape.dependencyEdges()).isEmpty();

        NormalizedSbom nonObjectEntries = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "bom-ref": "a", "name": "a" } ],
                  "dependencies": [ "not-an-object" ] }
                """);
        assertThat(nonObjectEntries.dependencyEdges()).isEmpty();

        NormalizedSbom nonArrayDependsOn = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "bom-ref": "a", "name": "a" } ],
                  "dependencies": [ { "ref": "a", "dependsOn": "b" } ] }
                """);
        assertThat(nonArrayDependsOn.dependencyEdges()).isEmpty();
    }

    @Test
    void providesIsIgnored() throws Exception {
        NormalizedSbom doc = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                  "components": [
                    { "type": "library", "bom-ref": "a", "name": "a" },
                    { "type": "library", "bom-ref": "b", "name": "b" }
                  ],
                  "dependencies": [ { "ref": "a", "provides": [ "b" ] } ] }
                """);
        assertThat(doc.dependencyEdges()).isEmpty();
    }

    @Test
    void noMetadataComponentOrNoBomRefGivesEmptyRootRefs() throws Exception {
        NormalizedSbom noMetadata = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [ { "type": "library", "bom-ref": "a", "name": "a" } ] }
                """);
        assertThat(noMetadata.dependencyRootRefs()).isEmpty();

        NormalizedSbom noBomRef = parse("""
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "component": { "type": "application", "name": "root" } },
                  "components": [ { "type": "library", "bom-ref": "a", "name": "a" } ] }
                """);
        assertThat(noBomRef.dependencyRootRefs()).isEmpty();
    }

    /* ------------------------------------------------------------------ */
    /* SPDX                                                                */
    /* ------------------------------------------------------------------ */

    @ParameterizedTest
    @ValueSource(strings = {
            "DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF",
            "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF"})
    void everyDependencyOfTypeGoesBToA(String type) throws Exception {
        NormalizedSbom doc = parseSpdx(spdxWithRelationship("SPDXRef-Package-a", type, "SPDXRef-Package-root"));
        assertThat(doc.dependencyEdges()).containsExactly(new DependencyEdge("SPDXRef-Package-root", "SPDXRef-Package-a"));
    }

    @Test
    void dependsOnGoesAToB() throws Exception {
        NormalizedSbom doc = parseSpdx(spdxWithRelationship("SPDXRef-Package-root", "DEPENDS_ON", "SPDXRef-Package-a"));
        assertThat(doc.dependencyEdges()).containsExactly(new DependencyEdge("SPDXRef-Package-root", "SPDXRef-Package-a"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "CONTAINS", "CONTAINED_BY", "DEPENDENCY_MANIFEST_OF", "STATIC_LINK", "DYNAMIC_LINK",
            "PREREQUISITE_FOR", "HAS_PREREQUISITE", "DESCRIBES"})
    void excludedTypesProduceNoEdges(String type) throws Exception {
        NormalizedSbom doc = parseSpdx(spdxWithRelationship("SPDXRef-Package-root", type, "SPDXRef-Package-a"));
        assertThat(doc.dependencyEdges()).isEmpty();
    }

    @Test
    void lowerCaseAndPaddedTypeNamesStillMatch() throws Exception {
        NormalizedSbom doc = parseSpdx(spdxWithRelationship("SPDXRef-Package-root", "  depends_on  ", "SPDXRef-Package-a"));
        assertThat(doc.dependencyEdges()).containsExactly(new DependencyEdge("SPDXRef-Package-root", "SPDXRef-Package-a"));
    }

    @Test
    void noneAndNoAssertionTargetsAreDropped() throws Exception {
        NormalizedSbom none = parseSpdx(spdxWithRelationship("SPDXRef-Package-root", "DEPENDS_ON", "NONE"));
        assertThat(none.dependencyEdges()).isEmpty();

        NormalizedSbom noAssertion = parseSpdx(spdxWithRelationship("SPDXRef-Package-root", "DEPENDS_ON", "NOASSERTION"));
        assertThat(noAssertion.dependencyEdges()).isEmpty();
    }

    @Test
    void rootRefsComeFromBothDocumentDescribesAndDescribesRelationship() throws Exception {
        NormalizedSbom doc = parseSpdx("""
                { "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "d",
                  "creationInfo": { "creators": [ "Tool: syft" ] },
                  "documentDescribes": [ "SPDXRef-Package-root1" ],
                  "packages": [
                    { "SPDXID": "SPDXRef-Package-root1", "name": "root1", "versionInfo": "1.0" },
                    { "SPDXID": "SPDXRef-Package-root2", "name": "root2", "versionInfo": "1.0" }
                  ],
                  "relationships": [
                    { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-root2" }
                  ] }
                """);
        assertThat(doc.dependencyRootRefs()).containsExactlyInAnyOrder("SPDXRef-Package-root1", "SPDXRef-Package-root2");
    }

    @Test
    void syftStyleDocumentOnlyTheDependencyOfChainBecomesEdges() throws Exception {
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
                    { "spdxElementId": "SPDXRef-Package-root", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-a" },
                    { "spdxElementId": "SPDXRef-Package-root", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-b" },
                    { "spdxElementId": "SPDXRef-Package-a", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-Package-root" }
                  ] }
                """);
        assertThat(doc.dependencyEdges()).containsExactly(new DependencyEdge("SPDXRef-Package-root", "SPDXRef-Package-a"));
    }

    /* ------------------------------------------------------------------ */
    /* Regression: the M1h presence set is unaffected on every fixture     */
    /* ------------------------------------------------------------------ */

    @Test
    void presenceSetStillMatchesM1hRulesRegardlessOfEdges() throws Exception {
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

    private static String spdxWithRelationship(String spdxElementId, String relationshipType, String relatedSpdxElement) {
        return """
                { "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "d",
                  "creationInfo": { "creators": [ "Tool: syft" ] },
                  "documentDescribes": [ "SPDXRef-Package-root" ],
                  "packages": [
                    { "SPDXID": "SPDXRef-Package-root", "name": "root", "versionInfo": "1.0" },
                    { "SPDXID": "SPDXRef-Package-a", "name": "a", "versionInfo": "1.0" }
                  ],
                  "relationships": [
                    { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-root" },
                    { "spdxElementId": "%s", "relationshipType": "%s", "relatedSpdxElement": "%s" }
                  ] }
                """.formatted(spdxElementId, relationshipType, relatedSpdxElement);
    }

}
