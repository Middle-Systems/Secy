package net.jdesive.secy.service.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.service.InvalidLifecycleStageException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * M1e (ROADMAP.md — "SBOM lifecycle stages + diffing"): CycloneDX {@code metadata.lifecycles[].phase}
 * → {@link SbomLifecycleStage}, and {@link SbomLifecycleStage#fromApiValue}. No Spring context, same
 * reasoning as {@code SecondaryIdentifierParsingTest}.
 */
class LifecycleStageParsingTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SbomParser parser =
            new SbomParser(new ObjectMapper(), new CycloneDXNormalizer(), new SpdxNormalizer());

    /* ------------------------------------------------------------------ */
    /* CycloneDX phase mapping                                            */
    /* ------------------------------------------------------------------ */

    @Test
    void preBuildMapsToSource() throws IOException {
        assertThat(parseLifecycles("pre-build").declaredLifecycleStage()).isEqualTo(SbomLifecycleStage.SOURCE);
    }

    @Test
    void buildMapsToBuild() throws IOException {
        assertThat(parseLifecycles("build").declaredLifecycleStage()).isEqualTo(SbomLifecycleStage.BUILD);
    }

    @Test
    void postBuildMapsToAnalyzed() throws IOException {
        assertThat(parseLifecycles("post-build").declaredLifecycleStage()).isEqualTo(SbomLifecycleStage.ANALYZED);
    }

    @Test
    void operationsMapsToDeployed() throws IOException {
        assertThat(parseLifecycles("operations").declaredLifecycleStage()).isEqualTo(SbomLifecycleStage.DEPLOYED);
    }

    @Test
    void designDiscoveryDecommissionAndCustomNameOnlyMapToNull() throws IOException {
        assertThat(parseLifecycles("design").declaredLifecycleStage()).isNull();
        assertThat(parseLifecycles("discovery").declaredLifecycleStage()).isNull();
        assertThat(parseLifecycles("decommission").declaredLifecycleStage()).isNull();

        JsonNode customNameOnly = document("""
                { "lifecycles": [ { "name": "my-custom-phase", "description": "something" } ] }""");
        assertThat(parser.parse(customNameOnly).declaredLifecycleStage()).isNull();
    }

    @Test
    void unrecognisedPhaseMapsToNull() throws IOException {
        assertThat(parseLifecycles("something-else-entirely").declaredLifecycleStage()).isNull();
    }

    @Test
    void conflictingPhasesMapToNull() throws IOException {
        JsonNode conflicting = document("""
                { "lifecycles": [ { "phase": "pre-build" }, { "phase": "build" } ] }""");
        assertThat(parser.parse(conflicting).declaredLifecycleStage()).isNull();
    }

    @Test
    void repeatedIdenticalPhasesMapToThatOneStage() throws IOException {
        JsonNode repeated = document("""
                { "lifecycles": [ { "phase": "build" }, { "phase": "build" } ] }""");
        assertThat(parser.parse(repeated).declaredLifecycleStage()).isEqualTo(SbomLifecycleStage.BUILD);
    }

    @Test
    void noMetadataOrNoLifecyclesArrayMapsToNull() throws IOException {
        // cyclonedx-mixed.json has metadata but no lifecycles[] at all.
        NormalizedSbom sbom = parser.parse(read("cyclonedx-mixed.json"));
        assertThat(sbom.declaredLifecycleStage()).isNull();
    }

    @Test
    void spdxFixturesAlwaysMapToNull() throws IOException {
        assertThat(parser.parse(read("spdx-2.2-minimal.json")).declaredLifecycleStage()).isNull();
        assertThat(parser.parse(read("spdx-2.3-mixed.json")).declaredLifecycleStage()).isNull();
    }

    @Test
    void theRealFixtureUsedByTheUploadTestsDeclaresBuild() throws IOException {
        NormalizedSbom sbom = parser.parse(read("cyclonedx-build-lifecycle.json"));
        assertThat(sbom.declaredLifecycleStage()).isEqualTo(SbomLifecycleStage.BUILD);
    }

    /* ------------------------------------------------------------------ */
    /* fromApiValue                                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void fromApiValueAcceptsAValidNameWithWhitespaceCaseInsensitively() {
        assertThat(SbomLifecycleStage.fromApiValue("  build  ")).isEqualTo(SbomLifecycleStage.BUILD);
        assertThat(SbomLifecycleStage.fromApiValue("DEPLOYED")).isEqualTo(SbomLifecycleStage.DEPLOYED);
    }

    @Test
    void fromApiValueTreatsBlankAsNull() {
        assertThat(SbomLifecycleStage.fromApiValue("")).isNull();
        assertThat(SbomLifecycleStage.fromApiValue("   ")).isNull();
    }

    @Test
    void fromApiValueTreatsNullAsNull() {
        assertThat(SbomLifecycleStage.fromApiValue(null)).isNull();
    }

    @Test
    void fromApiValueThrowsOnAnInvalidValue() {
        assertThatThrownBy(() -> SbomLifecycleStage.fromApiValue("prod"))
                .isInstanceOf(InvalidLifecycleStageException.class)
                .hasMessageContaining("prod")
                .hasMessageContaining("SOURCE")
                .hasMessageContaining("BUILD")
                .hasMessageContaining("ANALYZED")
                .hasMessageContaining("DEPLOYED");
    }

    /* ------------------------------------------------------------------ */

    private NormalizedSbom parseLifecycles(String phase) throws IOException {
        JsonNode node = document("{ \"lifecycles\": [ { \"phase\": \"" + phase + "\" } ] }");
        return parser.parse(node);
    }

    /** A minimal CycloneDX document with the given {@code metadata} object substituted in. */
    private JsonNode document(String metadataJson) throws IOException {
        JsonNode metadata = mapper.readTree(metadataJson);
        var root = mapper.createObjectNode();
        root.put("bomFormat", "CycloneDX");
        root.put("specVersion", "1.5");
        root.put("version", 1);
        root.set("metadata", metadata);
        return root;
    }

    private JsonNode read(String fixture) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("sbom/" + fixture)) {
            assertThat(in).as("sbom/%s", fixture).isNotNull();
            return mapper.readTree(in);
        }
    }

}
