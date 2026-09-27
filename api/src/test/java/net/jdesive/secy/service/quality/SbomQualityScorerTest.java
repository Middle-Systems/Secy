package net.jdesive.secy.service.quality;

import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.component.SbomFormat;
import net.jdesive.secy.persistence.entity.NtiaElement;
import net.jdesive.secy.persistence.entity.SbomQualityScore;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link SbomQualityScorer}, pure/static — no Spring context, same reasoning as
 * {@code QuantumVulnerabilityClassifierTest}. Drives {@link NormalizedSbom}/{@link NormalizedComponent}
 * directly rather than through a parser; {@code SbomQualityParsingTest} covers the parser side.
 */
class SbomQualityScorerTest {

    @Test
    void fullyCompliantDocumentScores100WithFullCoverage() {
        NormalizedComponent a = component("a", "1.0.0", "pkg:npm/a@1.0.0", "ref-a", "Acme");
        NormalizedComponent b = component("b", "2.0.0", "pkg:npm/b@2.0.0", "ref-b", "Acme");

        NormalizedSbom doc = NormalizedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .component(a)
                .component(b)
                .documentTimestamp(LocalDateTime.now())
                .author("Acme Build Team")
                .dependencyRelationshipRef("ref-a")
                .dependencyRelationshipRef("ref-b")
                .build();

        SbomQualityScore score = SbomQualityScorer.score(doc);
        assertThat(score).isNotNull();
        assertThat(score.getScore()).isEqualTo(100);
        assertThat(score.getSupplierCoverage()).isEqualTo(100);
        assertThat(score.getNameCoverage()).isEqualTo(100);
        assertThat(score.getVersionCoverage()).isEqualTo(100);
        assertThat(score.getUniqueIdCoverage()).isEqualTo(100);
        assertThat(score.getDependencyCoverage()).isEqualTo(100);
        assertThat(score.getHasAuthor()).isTrue();
        assertThat(score.getHasTimestamp()).isTrue();
        assertThat(score.getComponentsScored()).isEqualTo(2);
        assertThat(score.getMissingElements()).isEmpty();
    }

    @Test
    void emptyComponentPopulationIsNotScored() {
        NormalizedSbom doc = NormalizedSbom.builder().format(SbomFormat.CYCLONEDX).build();
        assertThat(SbomQualityScorer.score(doc)).isNull();
    }

    @Test
    void standaloneCbomWhereEveryComponentIsCryptoIsNotScored() {
        NormalizedComponent crypto = NormalizedComponent.builder()
                .name("RSA-2048").type("cryptographic-asset").bomRef("key-rsa").build();
        NormalizedSbom doc = NormalizedSbom.builder().format(SbomFormat.CYCLONEDX).component(crypto).build();
        assertThat(SbomQualityScorer.score(doc)).isNull();
    }

    @Test
    void mixedCryptoComponentsAreExcludedFromThePopulation() {
        NormalizedComponent library = component("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "ref-lodash", "Acme");
        NormalizedComponent crypto = NormalizedComponent.builder()
                .name("RSA-2048").type("cryptographic-asset").bomRef("key-rsa").build();

        NormalizedSbom doc = NormalizedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .component(library)
                .component(crypto)
                .documentTimestamp(LocalDateTime.now())
                .author("Acme")
                .dependencyRelationshipRef("ref-lodash")
                .build();

        SbomQualityScore score = SbomQualityScorer.score(doc);
        assertThat(score).isNotNull();
        // Only the library component is in the scored population, not the crypto asset.
        assertThat(score.getComponentsScored()).isEqualTo(1);
        assertThat(score.getScore()).isEqualTo(100);
    }

    @Test
    void uniqueIdentifierIsSatisfiedByPurlAloneCpeAloneOrHashAlone() {
        NormalizedComponent purlOnly = NormalizedComponent.builder()
                .name("a").version("1.0").purl("pkg:npm/a@1.0").build();
        NormalizedComponent cpeOnly = NormalizedComponent.builder()
                .name("b").version("1.0")
                .identifier(new NormalizedComponent.Identifier(
                        net.jdesive.secy.persistence.entity.SecondaryIdentifierType.CPE,
                        "cpe:2.3:a:acme:b:1.0:*:*:*:*:*:*:*", null, null, "test"))
                .build();
        NormalizedComponent hashOnly = NormalizedComponent.builder()
                .name("c").version("1.0")
                .hash(new NormalizedComponent.ComponentHashValue("SHA-256", "a".repeat(64)))
                .build();

        NormalizedSbom doc = NormalizedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .component(purlOnly).component(cpeOnly).component(hashOnly)
                .build();

        SbomQualityScore score = SbomQualityScorer.score(doc);
        assertThat(score).isNotNull();
        assertThat(score.getUniqueIdCoverage()).isEqualTo(100);
    }

    @Test
    void dependencyRelationshipFailsWhenBomRefIsNullEvenIfRelationshipSetIsNonEmpty() {
        NormalizedComponent noBomRef = NormalizedComponent.builder().name("a").version("1.0").build();
        NormalizedSbom doc = NormalizedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .component(noBomRef)
                .dependencyRelationshipRef("some-other-ref")
                .build();

        SbomQualityScore score = SbomQualityScorer.score(doc);
        assertThat(score).isNotNull();
        assertThat(score.getDependencyCoverage()).isZero();
    }

    @Test
    void flooringNeverRoundsUpToACleanHundred() {
        // 299 of 300 components have a supplier — 299/300 = 99.67%, must floor to 99, never 100.
        List<NormalizedComponent> components = new ArrayList<>();
        for (int i = 0; i < 300; i++) {
            String supplier = i < 299 ? "Acme" : null;
            components.add(NormalizedComponent.builder()
                    .name("c" + i).version("1.0").supplier(supplier).build());
        }
        NormalizedSbom.NormalizedSbomBuilder builder = NormalizedSbom.builder().format(SbomFormat.CYCLONEDX);
        components.forEach(builder::component);
        NormalizedSbom doc = builder.build();

        SbomQualityScore score = SbomQualityScorer.score(doc);
        assertThat(score).isNotNull();
        assertThat(score.getSupplierCoverage()).isEqualTo(99);
    }

    @Test
    void boundaryAroundTheFindingThreshold() {
        // n=10, all name/version/uniqueId/dependency complete (4 elements), hasTimestamp true,
        // nothing else -> sum = 4*10 + 10 = 50; score = floor(100*50/70) = 71 -> no finding.
        NormalizedSbom.NormalizedSbomBuilder above = NormalizedSbom.builder().format(SbomFormat.CYCLONEDX)
                .documentTimestamp(LocalDateTime.now());
        for (int i = 0; i < 10; i++) {
            String ref = "ref-" + i;
            above.component(NormalizedComponent.builder()
                    .name("c" + i).version("1.0").purl("pkg:npm/c" + i + "@1.0").bomRef(ref).build());
            above.dependencyRelationshipRef(ref);
        }
        SbomQualityScore aboveScore = SbomQualityScorer.score(above.build());
        assertThat(aboveScore.getScore()).isEqualTo(71);
        assertThat(aboveScore.getScore()).isGreaterThanOrEqualTo(SbomQualityScorer.FINDING_THRESHOLD);

        // Drop the timestamp too -> sum = 40; score = floor(4000/70) = 57 -> finding.
        NormalizedSbom.NormalizedSbomBuilder below = NormalizedSbom.builder().format(SbomFormat.CYCLONEDX);
        for (int i = 0; i < 10; i++) {
            String ref = "ref-" + i;
            below.component(NormalizedComponent.builder()
                    .name("c" + i).version("1.0").purl("pkg:npm/c" + i + "@1.0").bomRef(ref).build());
            below.dependencyRelationshipRef(ref);
        }
        SbomQualityScore belowScore = SbomQualityScorer.score(below.build());
        assertThat(belowScore.getScore()).isEqualTo(57);
        assertThat(belowScore.getScore()).isLessThan(SbomQualityScorer.FINDING_THRESHOLD);
    }

    @Test
    void toolsOnlyMeansNoAuthor() {
        NormalizedComponent c = component("a", "1.0", "pkg:npm/a@1.0", "ref-a", null);
        // Tools never populate NormalizedSbom.authors() — the normalizers keep the two concepts
        // separate at parse time, so this asserts the scorer's own side: an empty authors() list
        // means hasAuthor is false regardless of how many tools generated the document.
        NormalizedSbom doc = NormalizedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .component(c)
                .tool(new NormalizedSbom.NormalizedTool("syft", "0.98.0", null, "application"))
                .build();

        SbomQualityScore score = SbomQualityScorer.score(doc);
        assertThat(score).isNotNull();
        assertThat(score.getHasAuthor()).isFalse();
        assertThat(score.getMissingElements()).contains(NtiaElement.AUTHOR);
    }

    private static NormalizedComponent component(String name, String version, String purl, String bomRef,
                                                   String supplier) {
        return NormalizedComponent.builder()
                .name(name).version(version).purl(purl).bomRef(bomRef).supplier(supplier).build();
    }

}
