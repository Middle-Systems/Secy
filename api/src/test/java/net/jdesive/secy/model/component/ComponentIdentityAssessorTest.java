package net.jdesive.secy.model.component;

import net.jdesive.secy.persistence.entity.IdentityConfidence;
import net.jdesive.secy.persistence.entity.IdentityConflictType;
import net.jdesive.secy.persistence.entity.SecondaryIdentifierType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure, table-driven tests of {@link ComponentIdentityAssessor} (M1c, ROADMAP.md — "Canonical
 * component identity") — Pass A, entirely in-memory, no Spring/JPA. Every component is built
 * directly with {@link NormalizedComponent#builder()}, exactly the way the fixtures below exercise
 * the parsers first (see {@code SecondaryIdentifierParsingTest}), so these two test classes cover
 * "parsed correctly" and "assessed correctly" independently.
 */
class ComponentIdentityAssessorTest {

    @Test
    void purlOnlyWithNoIdentifiersIsUncorroborated() {
        NormalizedComponent c = NormalizedComponent.builder()
                .name("lodash").version("4.17.20").purl("pkg:npm/lodash@4.17.20")
                .build();

        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(c);
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.UNCORROBORATED);
        assertThat(result.conflicts()).isEmpty();
    }

    @Test
    void hashesOnlyNeverCountAsAgreementSoStillUncorroborated() {
        NormalizedComponent c = NormalizedComponent.builder()
                .name("lodash").version("4.17.20").purl("pkg:npm/lodash@4.17.20")
                .hash(new NormalizedComponent.ComponentHashValue("SHA-256", "a".repeat(64)))
                .build();

        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(c);
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.UNCORROBORATED);
        assertThat(result.conflicts()).isEmpty();
    }

    @Test
    void aMatchingCpeCorroborates() {
        NormalizedComponent c = log4j("2.14.1", cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"));

        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(c);
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.CORROBORATED);
        assertThat(result.conflicts()).isEmpty();
    }

    @Test
    void aCpeWithAMismatchedVersionConflicts() {
        NormalizedComponent c = log4j("2.14.1", cpe("cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*"));

        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(c);
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(result.conflicts()).extracting(ComponentIdentityAssessor.DetectedConflict::type)
                .containsExactly(IdentityConflictType.CPE_VERSION_MISMATCH);
    }

    @Test
    void aWhollyUnrelatedCpeConflictsOnBothNameAndVersion() {
        NormalizedComponent c = NormalizedComponent.builder()
                .name("lodash").version("4.17.20").purl("pkg:npm/lodash@4.17.20")
                .identifier(cpe("cpe:2.3:a:python:python:3.9.0:*:*:*:*:*:*:*"))
                .build();

        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(c);
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(result.conflicts()).extracting(ComponentIdentityAssessor.DetectedConflict::type)
                .containsExactlyInAnyOrder(
                        IdentityConflictType.CPE_NAME_MISMATCH, IdentityConflictType.CPE_VERSION_MISMATCH);
    }

    @Test
    void oneDotZeroAndOneDotZeroDotZeroAreTheSameVersion() {
        NormalizedComponent c = log4j("1.0", cpe("cpe:2.3:a:apache:log4j:1.0.0:*:*:*:*:*:*:*"));
        assertThat(ComponentIdentityAssessor.assess(c).conflicts()).isEmpty();
    }

    @Test
    void aVPrefixIsToleratedAcrossPurlAndCpe() {
        NormalizedComponent mux = NormalizedComponent.builder()
                .name("mux").version("v1.7.3").purl("pkg:golang/github.com/gorilla/mux@v1.7.3")
                .identifier(cpe("cpe:2.3:a:gorilla:mux:1.7.3:*:*:*:*:*:*:*"))
                .build();

        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(mux);
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.CORROBORATED);
        assertThat(result.conflicts()).isEmpty();
    }

    @Test
    void aWildcardVersionCpeSkipsTheVersionCheckEntirely() {
        NormalizedComponent c = log4j("9.9.9", cpe("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"));
        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(c);
        assertThat(result.conflicts()).isEmpty();
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.CORROBORATED);
    }

    @Test
    void aCpe22UriIsNotAssessedSoRemainsUncorroborated() {
        NormalizedComponent c = NormalizedComponent.builder()
                .name("openssl").version("1.1.1f")
                .identifier(cpe22("cpe:/a:openssl:openssl:1.1.1f"))
                .build();

        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(c);
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.UNCORROBORATED);
        assertThat(result.conflicts()).isEmpty();
    }

    @Test
    void aNoPurlComponentWithAMatchingCpeStillCorroborates() {
        NormalizedComponent c = NormalizedComponent.builder()
                .name("OpenSSL").version("1.1.1g")
                .identifier(cpe("cpe:2.3:a:openssl:openssl:1.1.1g:*:*:*:*:*:*:*"))
                .build();

        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(c);
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.CORROBORATED);
        assertThat(result.conflicts()).isEmpty();
    }

    @Test
    void aSwidNameOrVersionMismatchConflicts() {
        NormalizedComponent nameMismatch = NormalizedComponent.builder()
                .name("acme-agent").version("2.1")
                .identifier(new NormalizedComponent.Identifier(
                        SecondaryIdentifierType.SWID, "tag-1", "Totally Different", "2.1", "test"))
                .build();
        assertThat(ComponentIdentityAssessor.assess(nameMismatch).conflicts())
                .extracting(ComponentIdentityAssessor.DetectedConflict::type)
                .containsExactly(IdentityConflictType.SWID_NAME_MISMATCH);

        NormalizedComponent versionMismatch = NormalizedComponent.builder()
                .name("acme-agent").version("2.1")
                .identifier(new NormalizedComponent.Identifier(
                        SecondaryIdentifierType.SWID, "tag-2", "Acme Agent", "2.0", "test"))
                .build();
        assertThat(ComponentIdentityAssessor.assess(versionMismatch).conflicts())
                .extracting(ComponentIdentityAssessor.DetectedConflict::type)
                .containsExactly(IdentityConflictType.SWID_VERSION_MISMATCH);

        NormalizedComponent agrees = NormalizedComponent.builder()
                .name("acme-agent").version("2.1")
                .identifier(new NormalizedComponent.Identifier(
                        SecondaryIdentifierType.SWID, "tag-3", "Acme Agent", "2.1", "test"))
                .build();
        ComponentIdentityAssessor.IdentityAssessment agreeResult = ComponentIdentityAssessor.assess(agrees);
        assertThat(agreeResult.conflicts()).isEmpty();
        assertThat(agreeResult.confidence()).isEqualTo(IdentityConfidence.CORROBORATED);
    }

    @Test
    void aSameSha256ValueUnderBothSpellingsIsNotADisagreement() {
        NormalizedComponent c = NormalizedComponent.builder()
                .name("double-hash").version("1.0.0")
                .hash(new NormalizedComponent.ComponentHashValue("SHA-256", "a".repeat(64)))
                .hash(new NormalizedComponent.ComponentHashValue("SHA256", "a".repeat(64)))
                .build();
        assertThat(ComponentIdentityAssessor.assess(c).conflicts()).isEmpty();
    }

    @Test
    void twoDifferentSha256ValuesDisagree() {
        NormalizedComponent c = NormalizedComponent.builder()
                .name("double-hash").version("1.0.0")
                .hash(new NormalizedComponent.ComponentHashValue("SHA-256", "1".repeat(64)))
                .hash(new NormalizedComponent.ComponentHashValue("SHA-256", "2".repeat(64)))
                .build();

        ComponentIdentityAssessor.IdentityAssessment result = ComponentIdentityAssessor.assess(c);
        assertThat(result.confidence()).isEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(result.conflicts()).extracting(ComponentIdentityAssessor.DetectedConflict::type)
                .containsExactly(IdentityConflictType.HASH_ALGORITHM_DISAGREEMENT);
    }

    /* ------------------------------------------------------------------ */

    private static NormalizedComponent log4j(String version, NormalizedComponent.Identifier... identifiers) {
        NormalizedComponent.NormalizedComponentBuilder builder = NormalizedComponent.builder()
                .name("log4j-core").version(version)
                .purl("pkg:maven/org.apache.logging.log4j/log4j-core@" + version);
        for (NormalizedComponent.Identifier identifier : identifiers) {
            builder.identifier(identifier);
        }
        return builder.build();
    }

    private static NormalizedComponent.Identifier cpe(String value) {
        return SecondaryIdentifiers.cpe(value, "test");
    }

    private static NormalizedComponent.Identifier cpe22(String value) {
        return SecondaryIdentifiers.cpe(value, "test");
    }

}
