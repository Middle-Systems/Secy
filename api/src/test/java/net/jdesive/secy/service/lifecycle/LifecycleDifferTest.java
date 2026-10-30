package net.jdesive.secy.service.lifecycle;

import net.jdesive.secy.model.lifecycle.StageComponent;
import net.jdesive.secy.service.lifecycle.LifecycleDiffer.Drift;
import net.jdesive.secy.service.lifecycle.LifecycleDiffer.LifecycleDiff;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link LifecycleDiffer} in isolation — no Spring, no JPA, exhaustive over the classification rules
 * and the ecosystem-coverage noise control.
 */
class LifecycleDifferTest {

    @Test
    void unexpectedComponentIsDetectedWhenEcosystemIsCovered() {
        List<StageComponent> baseline = List.of(npm("lodash", "4.17.20"));
        List<StageComponent> observed = List.of(npm("lodash", "4.17.20"), npm("acme-internal-utils", "99.0.0"));

        LifecycleDiff diff = LifecycleDiffer.diff(baseline, observed);

        assertThat(diff.unexpected()).hasSize(1);
        assertThat(diff.unexpected().get(0).identityKey()).isEqualTo("npm/acme-internal-utils");
        assertThat(diff.versionMismatches()).isEmpty();
    }

    @Test
    void removedIsComputedButNeverRaised() {
        List<StageComponent> baseline = List.of(npm("lodash", "4.17.20"), npm("left-pad", "1.3.0"));
        List<StageComponent> observed = List.of(npm("lodash", "4.17.20"));

        LifecycleDiff diff = LifecycleDiffer.diff(baseline, observed);

        assertThat(diff.removedIdentityKeys()).containsExactly("npm/left-pad");
        assertThat(diff.unexpected()).isEmpty();
        assertThat(diff.versionMismatches()).isEmpty();
    }

    @Test
    void versionMismatchWhenObservedHasAVersionBaselineNeverDeclared() {
        List<StageComponent> baseline = List.of(npm("lodash", "4.17.20"));
        List<StageComponent> observed = List.of(npm("lodash", "4.17.21"));

        LifecycleDiff diff = LifecycleDiffer.diff(baseline, observed);

        assertThat(diff.versionMismatches()).hasSize(1);
        Drift drift = diff.versionMismatches().get(0);
        assertThat(drift.identityKey()).isEqualTo("npm/lodash");
        assertThat(drift.observedVersions()).containsExactly("4.17.21");
        assertThat(drift.baselineVersions()).containsExactly("4.17.20");
    }

    @Test
    void vPrefixIsNormalizedSoItDoesNotFalselyMismatch() {
        List<StageComponent> baseline = List.of(npm("mux", "v1.7.3"));
        List<StageComponent> observed = List.of(npm("mux", "1.7.3"));

        LifecycleDiff diff = LifecycleDiffer.diff(baseline, observed);

        assertThat(diff.versionMismatches()).isEmpty();
    }

    @Test
    void rangeBlankNullLatestAndWildcardBaselinesNeverProduceAMismatch() {
        // None of these baseline "versions" are concrete, so no mismatch is possible, whatever
        // observed declares.
        assertThat(LifecycleDiffer.diff(List.of(npm("a", "^4.17.0")), List.of(npm("a", "4.17.5")))
                .versionMismatches()).isEmpty();
        assertThat(LifecycleDiffer.diff(List.of(npm("b", "")), List.of(npm("b", "1.0.0")))
                .versionMismatches()).isEmpty();
        assertThat(LifecycleDiffer.diff(List.of(npm("c", null)), List.of(npm("c", "1.0.0")))
                .versionMismatches()).isEmpty();
        assertThat(LifecycleDiffer.diff(List.of(npm("d", "latest")), List.of(npm("d", "1.0.0")))
                .versionMismatches()).isEmpty();
        assertThat(LifecycleDiffer.diff(List.of(npm("e", "1.x")), List.of(npm("e", "1.2.3")))
                .versionMismatches()).isEmpty();
        assertThat(LifecycleDiffer.diff(List.of(npm("f", "1.X.0")), List.of(npm("f", "1.2.0")))
                .versionMismatches()).isEmpty();
    }

    @Test
    void observedExtraVersionBeyondBaselineSetIsAMismatch() {
        // Two rows in baseline for the same identity (the known ComponentIdentity collapse) means two
        // concrete versions in its group; observed adds a third that neither baseline row declared.
        List<StageComponent> baseline = List.of(npm("shaded", "1.0.0"), npm("shaded", "1.0.1"));
        List<StageComponent> observed = List.of(npm("shaded", "1.0.2"));

        LifecycleDiff diff = LifecycleDiffer.diff(baseline, observed);

        assertThat(diff.versionMismatches()).hasSize(1);
        assertThat(diff.versionMismatches().get(0).observedVersions()).containsExactly("1.0.2");
        assertThat(diff.versionMismatches().get(0).baselineVersions()).containsExactly("1.0.0", "1.0.1");
    }

    @Test
    void multipleRowsPerIdentityCollapseIntoOneGroup() {
        List<StageComponent> baseline = List.of(npm("shaded", "1.0.0"));
        List<StageComponent> observed = List.of(npm("shaded", "1.0.0"), npm("shaded", "1.0.0"));

        LifecycleDiff diff = LifecycleDiffer.diff(baseline, observed);

        assertThat(diff.unexpected()).isEmpty();
        assertThat(diff.versionMismatches()).isEmpty();
        assertThat(diff.removedIdentityKeys()).isEmpty();
    }

    @Test
    void nullIdentityKeyIsIgnored() {
        StageComponent noIdentity = new StageComponent(UUID.randomUUID(), null, "mystery", "1.0.0", null);
        LifecycleDiff diff = LifecycleDiffer.diff(List.of(), List.of(noIdentity));

        assertThat(diff.unexpected()).isEmpty();
        assertThat(diff.outOfCoverage()).isZero();
    }

    @Test
    void debOnlyInObservedWithNoDebInBaselineIsOutOfCoverage() {
        List<StageComponent> baseline = List.of(npm("app-dep", "1.0.0"));
        List<StageComponent> observed = List.of(npm("app-dep", "1.0.0"), deb("openssl", "3.0.0"));

        LifecycleDiff diff = LifecycleDiffer.diff(baseline, observed);

        assertThat(diff.unexpected()).isEmpty();
        assertThat(diff.outOfCoverage()).isEqualTo(1);
    }

    @Test
    void aNewNpmIdentityIsFlaggedWhenBaselineAlreadyHasNpm() {
        List<StageComponent> baseline = List.of(npm("lodash", "4.17.20"));
        List<StageComponent> observed = List.of(npm("lodash", "4.17.20"), npm("brand-new", "1.0.0"));

        LifecycleDiff diff = LifecycleDiffer.diff(baseline, observed);

        assertThat(diff.unexpected()).hasSize(1);
        assertThat(diff.unexpected().get(0).identityKey()).isEqualTo("npm/brand-new");
    }

    @Test
    void nameSlashKeysAreTheirOwnEcosystem() {
        StageComponent noPurl = new StageComponent(UUID.randomUUID(), "name/openssl", "OpenSSL", "1.1.1g", null);
        List<StageComponent> baseline = List.of(noPurl);
        List<StageComponent> observedExtra =
                List.of(noPurl, new StageComponent(UUID.randomUUID(), "name/curl", "curl", "8.0.0", null));

        LifecycleDiff diff = LifecycleDiffer.diff(baseline, observedExtra);

        // baseline has a "name" ecosystem identity (openssl), so a new "name" identity is covered.
        assertThat(diff.unexpected()).hasSize(1);
        assertThat(diff.unexpected().get(0).identityKey()).isEqualTo("name/curl");
    }

    @Test
    void emptyBaselineMeansEverythingIsOutOfCoverage() {
        List<StageComponent> observed = List.of(npm("lodash", "4.17.20"), deb("openssl", "3.0.0"));

        LifecycleDiff diff = LifecycleDiffer.diff(List.of(), observed);

        assertThat(diff.unexpected()).isEmpty();
        assertThat(diff.outOfCoverage()).isEqualTo(2);
    }

    @Test
    void representativeIsDeterministicByLowestComponentId() {
        UUID low = UUID.fromString("00000000-0000-0000-0000-000000000001");
        UUID high = UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff");

        // Two rows for the same identity, at different versions so the group has to pick one
        // representative — same identity, covered ecosystem (baseline has npm/other), so this is a
        // VERSION_MISMATCH candidate whose representative must be picked deterministically.
        StageComponent low1 = new StageComponent(low, "npm/pkg", "pkg", "2.0.0", "pkg:npm/pkg@2.0.0");
        StageComponent high2 = new StageComponent(high, "npm/pkg", "pkg", "2.0.1", "pkg:npm/pkg@2.0.1");
        List<StageComponent> baseline = List.of(npm("other", "1.0.0"), npm("pkg", "1.0.0"));

        LifecycleDiff diffA = LifecycleDiffer.diff(baseline, List.of(high2, low1));
        LifecycleDiff diffB = LifecycleDiffer.diff(baseline, List.of(low1, high2));

        assertThat(diffA.versionMismatches()).hasSize(1);
        assertThat(diffB.versionMismatches()).hasSize(1);
        assertThat(diffA.versionMismatches().get(0).representative().componentId())
                .isEqualTo(diffB.versionMismatches().get(0).representative().componentId())
                .isEqualTo(low);
    }

    private static StageComponent npm(String name, String version) {
        return new StageComponent(UUID.randomUUID(), "npm/" + name, name, version, "pkg:npm/" + name);
    }

    private static StageComponent deb(String name, String version) {
        return new StageComponent(UUID.randomUUID(), "deb/" + name, name, version, "pkg:deb/" + name);
    }

}
