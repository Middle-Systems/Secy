package net.jdesive.secy.service.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.component.SbomFormat;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The point of the normalized model: two documents describing the same dependencies must produce the
 * same {@link NormalizedComponent}s, so nothing downstream of the parser can behave differently
 * depending on which format was uploaded.
 *
 * <p>{@code cyclonedx-mixed.json} and {@code spdx-2.3-mixed.json} are hand-written to describe the
 * <em>same three components</em> — one with a PURL, one with two licenses, one with no PURL at all —
 * so the equivalence assertions below are meaningful rather than vacuous.
 *
 * <p>No Spring context: the parsers are plain objects, which is most of why the parse target is a
 * record and not an entity.
 */
class NormalizedComponentMappingTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SbomParser parser =
            new SbomParser(new ObjectMapper(), new CycloneDXNormalizer(), new SpdxNormalizer());

    /* ------------------------------------------------------------------ */
    /* Equivalence — the headline claim                                   */
    /* ------------------------------------------------------------------ */

    @Test
    void cycloneDxAndSpdxProduceEquivalentComponentsWhereTheSourceDataOverlaps() throws IOException {
        List<NormalizedComponent> cdx = parse("cyclonedx-mixed.json").components();
        List<NormalizedComponent> spdx = parse("spdx-2.3-mixed.json").components();

        assertThat(cdx).hasSize(3);
        assertThat(spdx).hasSize(3);

        for (String name : List.of("lodash", "log4j-core", "OpenSSL")) {
            NormalizedComponent a = byName(cdx, name);
            NormalizedComponent b = byName(spdx, name);

            assertThat(b.name()).as("%s name", name).isEqualTo(a.name());
            assertThat(b.version()).as("%s version", name).isEqualTo(a.version());
            assertThat(b.purl()).as("%s purl", name).isEqualTo(a.purl());
            assertThat(b.ecosystem()).as("%s ecosystem", name).isEqualTo(a.ecosystem());
            assertThat(b.type()).as("%s type", name).isEqualTo(a.type());
            assertThat(b.description()).as("%s description", name).isEqualTo(a.description());
            // The identity key is what correlation upserts on. If the two formats disagreed here, a
            // product that switched SBOM generators would duplicate every alert it has.
            assertThat(b.identityKey()).as("%s identity", name).isEqualTo(a.identityKey());
        }
    }

    /* ------------------------------------------------------------------ */
    /* CycloneDX                                                          */
    /* ------------------------------------------------------------------ */

    @Test
    void cycloneDxMapsEveryFieldIncludingTheRootComponentAndTools() throws IOException {
        NormalizedSbom sbom = parse("cyclonedx-mixed.json");

        assertThat(sbom.format()).isEqualTo(SbomFormat.CYCLONEDX);
        assertThat(sbom.specVersion()).isEqualTo("1.5");
        assertThat(sbom.version()).isEqualTo(3);

        // metadata.component is the product, not a dependency: held separately, never correlated.
        assertThat(sbom.rootComponent()).isNotNull();
        assertThat(sbom.rootComponent().name()).isEqualTo("acme-web");
        assertThat(sbom.components()).extracting(NormalizedComponent::name)
                .doesNotContain("acme-web");

        assertThat(sbom.tools()).singleElement()
                .satisfies(tool -> {
                    assertThat(tool.name()).isEqualTo("syft");
                    assertThat(tool.version()).isEqualTo("0.98.0");
                    assertThat(tool.group()).isEqualTo("anchore");
                });

        NormalizedComponent lodash = byName(sbom.components(), "lodash");
        assertThat(lodash.purl()).isEqualTo("pkg:npm/lodash@4.17.20");
        assertThat(lodash.ecosystem()).isEqualTo("npm");
        assertThat(lodash.bomRef()).isEqualTo("pkg:npm/lodash@4.17.20");
        assertThat(lodash.licenses()).containsExactly("MIT");
        assertThat(lodash.externalReferences())
                .extracting(NormalizedComponent.ExternalReference::url)
                .containsExactly("https://lodash.com/", "https://github.com/lodash/lodash");
    }

    @Test
    void multipleLicensesSurviveInDocumentOrder() throws IOException {
        NormalizedComponent log4j = byName(parse("cyclonedx-mixed.json").components(), "log4j-core");

        assertThat(log4j.licenses()).containsExactly("Apache-2.0", "MIT");
        assertThat(log4j.ecosystem()).isEqualTo("Maven");
        assertThat(log4j.identityKey()).isEqualTo("maven/org.apache.logging.log4j:log4j-core");
    }

    @Test
    void aComponentWithNoPurlStillNormalizesAndGetsANameBasedIdentity() throws IOException {
        NormalizedComponent openssl = byName(parse("cyclonedx-mixed.json").components(), "OpenSSL");

        assertThat(openssl.purl()).isNull();
        assertThat(openssl.ecosystem()).isNull();
        // The "name/" prefix keeps this namespace disjoint from the PURL one.
        assertThat(openssl.identityKey()).isEqualTo("name/openssl");
    }

    /* ------------------------------------------------------------------ */
    /* SPDX                                                               */
    /* ------------------------------------------------------------------ */

    @Test
    void spdxFindsThePurlInsideExternalRefs() throws IOException {
        NormalizedComponent lodash = byName(parse("spdx-2.3-mixed.json").components(), "lodash");

        assertThat(lodash.purl()).isEqualTo("pkg:npm/lodash@4.17.20");
        assertThat(lodash.ecosystem()).isEqualTo("npm");
        // The PURL is promoted out of externalRefs; everything else in there stays a reference.
        assertThat(lodash.externalReferences())
                .extracting(NormalizedComponent.ExternalReference::url)
                .containsExactly("https://lodash.com/");
    }

    @Test
    void spdxKeepsBothLicenseFieldsAndDropsTheNoValueSentinels() throws IOException {
        List<NormalizedComponent> components = parse("spdx-2.3-mixed.json").components();

        // licenseConcluded first, then licenseDeclared, deduped.
        assertThat(byName(components, "log4j-core").licenses()).containsExactly("Apache-2.0", "MIT");
        // NOASSERTION / NONE are "no information", not licenses.
        assertThat(byName(components, "OpenSSL").licenses()).isEmpty();
    }

    @Test
    void spdxRootPackageIsSeparatedFromTheDependencies() throws IOException {
        NormalizedSbom sbom = parse("spdx-2.3-mixed.json");

        assertThat(sbom.format()).isEqualTo(SbomFormat.SPDX);
        assertThat(sbom.specVersion()).isEqualTo("SPDX-2.3");
        assertThat(sbom.version()).isEqualTo(1);
        assertThat(sbom.rootComponent()).isNotNull();
        assertThat(sbom.rootComponent().name()).isEqualTo("acme-web");
        assertThat(sbom.rootComponent().type()).isEqualTo("application");
        assertThat(sbom.components()).extracting(NormalizedComponent::name)
                .containsExactlyInAnyOrder("lodash", "log4j-core", "OpenSSL");
    }

    @Test
    void spdx22HasNoPurposeFieldAndNoDocumentDescribesShorthand() throws IOException {
        NormalizedSbom sbom = parse("spdx-2.2-minimal.json");

        assertThat(sbom.specVersion()).isEqualTo("SPDX-2.2");
        // The root came from the DESCRIBES relationship alone — 2.2 documents often omit
        // documentDescribes entirely.
        assertThat(sbom.rootComponent().name()).isEqualTo("acme-batch");
        assertThat(sbom.components()).extracting(NormalizedComponent::name)
                .containsExactlyInAnyOrder("github.com/gorilla/mux", "zlib");

        NormalizedComponent mux = byName(sbom.components(), "github.com/gorilla/mux");
        assertThat(mux.ecosystem()).isEqualTo("Go");
        assertThat(mux.version()).isEqualTo("v1.7.3");
        // No primaryPackagePurpose in 2.2 — best-effort default rather than a null column.
        assertThat(mux.type()).isEqualTo("library");
        assertThat(mux.identityKey()).isEqualTo("golang/github.com/gorilla/mux");

        // versionInfo: NOASSERTION means "unknown", not a version string called NOASSERTION.
        assertThat(byName(sbom.components(), "zlib").version()).isNull();
    }

    @Test
    void spdxToolCreatorsAreSplitOnlyWhenAVersionActuallyFollows() throws IOException {
        assertThat(parse("spdx-2.3-mixed.json").tools()).singleElement()
                .satisfies(tool -> {
                    assertThat(tool.name()).isEqualTo("syft");
                    assertThat(tool.version()).isEqualTo("0.98.0");
                });

        // "Tool: cyclonedx-gomod" is a hyphenated NAME, not name-version. Organization:/Person:
        // creators are not tools and are dropped.
        assertThat(parse("spdx-2.2-minimal.json").tools()).singleElement()
                .satisfies(tool -> {
                    assertThat(tool.name()).isEqualTo("cyclonedx-gomod");
                    assertThat(tool.version()).isNull();
                });
    }

    /* ------------------------------------------------------------------ */
    /* Format detection                                                   */
    /* ------------------------------------------------------------------ */

    @Test
    void detectsCycloneDx() throws IOException {
        assertThat(parse("cyclonedx-mixed.json").format()).isEqualTo(SbomFormat.CYCLONEDX);
    }

    @Test
    void detectsSpdx22AndSpdx23() throws IOException {
        assertThat(parse("spdx-2.2-minimal.json").format()).isEqualTo(SbomFormat.SPDX);
        assertThat(parse("spdx-2.3-mixed.json").format()).isEqualTo(SbomFormat.SPDX);
    }

    @Test
    void aDocumentThatIsNeitherFormatIsRejectedByName() throws IOException {
        JsonNode body = read("not-an-sbom.json");

        assertThatThrownBy(() -> parser.parse(body))
                .isInstanceOf(UnsupportedSbomFormatException.class)
                .hasMessageContaining("bomFormat")
                .hasMessageContaining("spdxVersion")
                .hasMessageContaining("CycloneDX")
                .hasMessageContaining("SPDX");
    }

    @Test
    void anSpdxRevisionSecyDoesNotReadIsRejectedByVersion() throws IOException {
        JsonNode body = read("spdx-3.0-unsupported.json");

        assertThatThrownBy(() -> parser.parse(body))
                .isInstanceOf(UnsupportedSbomFormatException.class)
                .hasMessageContaining("SPDX-3.0")
                .hasMessageContaining("SPDX-2.2, SPDX-2.3");
    }

    @Test
    void aBodyThatIsNotAJsonObjectIsRejected() {
        assertThatThrownBy(() -> parser.parse(mapper.createArrayNode()))
                .isInstanceOf(UnsupportedSbomFormatException.class)
                .hasMessageContaining("JSON object");
    }

    @Test
    void unknownFieldsDoNotFailTheParse() throws IOException {
        // Forward compatibility: a newer CycloneDX or a producer's extension must not cost the user
        // every component in the document.
        JsonNode body = read("cyclonedx-mixed.json");
        ((com.fasterxml.jackson.databind.node.ObjectNode) body).put("thisFieldDoesNotExistYet", true);

        assertThat(parser.parse(body).components()).hasSize(3);
    }

    /* ------------------------------------------------------------------ */

    private NormalizedSbom parse(String fixture) throws IOException {
        return parser.parse(read(fixture));
    }

    private JsonNode read(String fixture) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("sbom/" + fixture)) {
            assertThat(in).as("sbom/%s", fixture).isNotNull();
            return mapper.readTree(in);
        }
    }

    private static NormalizedComponent byName(List<NormalizedComponent> components, String name) {
        Optional<NormalizedComponent> match = components.stream()
                .filter(c -> name.equals(c.name()))
                .findFirst();
        assertThat(match).as("component named %s", name).isPresent();
        return match.get();
    }

}
