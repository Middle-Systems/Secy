package net.jdesive.secy.service.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.persistence.entity.SecondaryIdentifierType;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M1c (ROADMAP.md — "Canonical component identity"): CycloneDX {@code component.cpe}/{@code swid}
 * and SPDX {@code externalRefs[].cpe23Type}/{@code cpe22Type}/{@code swid} promoted to
 * {@link NormalizedComponent.Identifier}s. No Spring context — same reasoning as
 * {@link NormalizedComponentMappingTest}.
 */
class SecondaryIdentifierParsingTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SbomParser parser =
            new SbomParser(new ObjectMapper(), new CycloneDXNormalizer(), new SpdxNormalizer());

    /* ------------------------------------------------------------------ */
    /* CycloneDX                                                          */
    /* ------------------------------------------------------------------ */

    @Test
    void cycloneDxCpeIsParsedLowerCasedWithDeclaredNameAndVersion() throws IOException {
        NormalizedComponent log4j = byName(parse("cyclonedx-identifiers.json").components(), "log4j-core");

        assertThat(log4j.identifiers()).hasSize(1);
        NormalizedComponent.Identifier cpe = log4j.identifiers().get(0);
        assertThat(cpe.type()).isEqualTo(SecondaryIdentifierType.CPE);
        assertThat(cpe.value()).isEqualTo("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");
        assertThat(cpe.declaredName()).isEqualTo("log4j");
        assertThat(cpe.declaredVersion()).isEqualTo("2.14.1");
        assertThat(cpe.source()).isEqualTo("cyclonedx:component.cpe");
    }

    @Test
    void cycloneDxSwidIsParsedWithNameAndVersion() throws IOException {
        NormalizedComponent agent = byName(parse("cyclonedx-identifiers.json").components(), "acme-agent");

        assertThat(agent.identifiers()).hasSize(1);
        NormalizedComponent.Identifier swid = agent.identifiers().get(0);
        assertThat(swid.type()).isEqualTo(SecondaryIdentifierType.SWID);
        assertThat(swid.value()).isEqualTo("swidgen-1234-5678-abcd");
        assertThat(swid.declaredName()).isEqualTo("Acme Agent");
        assertThat(swid.declaredVersion()).isEqualTo("2.0");
        assertThat(swid.source()).isEqualTo("cyclonedx:component.swid");
    }

    @Test
    void aTaglessSwidIsDropped() throws IOException {
        NormalizedComponent noTag = byName(parse("cyclonedx-identifiers.json").components(), "no-tagid-comp");
        assertThat(noTag.identifiers()).isEmpty();
    }

    @Test
    void anOverLongCpeIsDroppedNotTruncated() throws IOException {
        NormalizedComponent longCpe = byName(parse("cyclonedx-identifiers.json").components(), "long-cpe-comp");
        assertThat(longCpe.identifiers()).isEmpty();
    }

    @Test
    void theRootComponentsCpeIsParsedToo() throws IOException {
        NormalizedSbom sbom = parse("cyclonedx-identifiers.json");
        assertThat(sbom.rootComponent()).isNotNull();
        assertThat(sbom.rootComponent().identifiers()).hasSize(1);
        assertThat(sbom.rootComponent().identifiers().get(0).type()).isEqualTo(SecondaryIdentifierType.CPE);
        assertThat(sbom.rootComponent().identifiers().get(0).value())
                .isEqualTo("cpe:2.3:a:acme:acme-identifiers-app:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void identityKeyIsUnaffectedByIdentifiers() throws IOException {
        NormalizedComponent log4j = byName(parse("cyclonedx-identifiers.json").components(), "log4j-core");
        assertThat(log4j.identifiers()).isNotEmpty();
        assertThat(log4j.identityKey()).isEqualTo("maven/org.apache.logging.log4j:log4j-core");

        // A component with no identifiers at all gets the exact same identityKey shape.
        NormalizedComponent lodash = byName(parse("cyclonedx-identifiers.json").components(), "lodash");
        assertThat(lodash.identityKey()).isEqualTo("npm/lodash");
    }

    /* ------------------------------------------------------------------ */
    /* SPDX                                                               */
    /* ------------------------------------------------------------------ */

    @Test
    void spdxCpe23AndCpe22AndSwidAreAllPromoted() throws IOException {
        NormalizedComponent openssl = byName(parse("spdx-2.3-identifiers.json").components(), "openssl");

        List<NormalizedComponent.Identifier> cpe23 = openssl.identifiers().stream()
                .filter(i -> i.type() == SecondaryIdentifierType.CPE)
                .filter(i -> i.source().equals("spdx:externalRefs.cpe23Type"))
                .toList();
        // Two distinct cpe23Type values after dedupe (one duplicate differing only by case).
        assertThat(cpe23).hasSize(2);
        assertThat(cpe23).extracting(NormalizedComponent.Identifier::value)
                .containsExactlyInAnyOrder(
                        "cpe:2.3:a:openssl:openssl:1.1.1f:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl:1.1.1g:*:*:*:*:*:*:*");

        List<NormalizedComponent.Identifier> cpe22 = openssl.identifiers().stream()
                .filter(i -> i.source().equals("spdx:externalRefs.cpe22Type"))
                .toList();
        assertThat(cpe22).singleElement().satisfies(i -> {
            assertThat(i.type()).isEqualTo(SecondaryIdentifierType.CPE);
            assertThat(i.value()).isEqualTo("cpe:/a:openssl:openssl:1.1.1f");
            // 2.2 URIs are stored but not further parsed.
            assertThat(i.declaredName()).isNull();
            assertThat(i.declaredVersion()).isNull();
        });

        List<NormalizedComponent.Identifier> swid = openssl.identifiers().stream()
                .filter(i -> i.type() == SecondaryIdentifierType.SWID)
                .toList();
        assertThat(swid).singleElement().satisfies(i -> {
            // "swid:" prefix stripped.
            assertThat(i.value()).isEqualTo("2df9de35-0aff-4a86-ace6-f7dddd1ade4c");
            assertThat(i.source()).isEqualTo("spdx:externalRefs.swid");
        });
    }

    @Test
    void spdxCaseInsensitiveDuplicateCpe23RefsDedupe() throws IOException {
        NormalizedComponent openssl = byName(parse("spdx-2.3-identifiers.json").components(), "openssl");
        long distinctCpe23Values = openssl.identifiers().stream()
                .filter(i -> i.source().equals("spdx:externalRefs.cpe23Type"))
                .map(NormalizedComponent.Identifier::value)
                .distinct()
                .count();
        assertThat(distinctCpe23Values).isEqualTo(2);
    }

    @Test
    void promotedRefsStillAppearInExternalReferences() throws IOException {
        // Regression guard: promoting a ref to an Identifier must not remove it from the plain
        // externalReferences list the UI reads (roadmap decision: "stay in sbom_reference too").
        NormalizedComponent openssl = byName(parse("spdx-2.3-identifiers.json").components(), "openssl");
        assertThat(openssl.externalReferences())
                .extracting(NormalizedComponent.ExternalReference::url)
                .contains(
                        "cpe:2.3:a:openssl:openssl:1.1.1f:*:*:*:*:*:*:*",
                        "CPE:2.3:A:OPENSSL:OPENSSL:1.1.1f:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl:1.1.1g:*:*:*:*:*:*:*",
                        "cpe:/a:openssl:openssl:1.1.1f",
                        "swid:2df9de35-0aff-4a86-ace6-f7dddd1ade4c");
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
