package net.jdesive.secy.correlation.version;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The orderings, one nested class per ecosystem.
 *
 * <p>Every case here is a version pair that a naive numeric comparison — the one this package
 * replaces — gets wrong. Correlation is only as good as these: a scheme that mis-orders
 * {@code 1.0.0-rc1} against {@code 1.0.0} either invents an alert or hides one, and both failures
 * look identical from the outside.
 */
class VersionSchemeTest {

    private static void assertBelow(VersionScheme scheme, String lower, String higher) {
        assertThat(scheme.compare(lower, higher))
                .as("%s: %s < %s", scheme.name(), lower, higher)
                .isNegative();
        assertThat(scheme.compare(higher, lower))
                .as("%s: %s > %s", scheme.name(), higher, lower)
                .isPositive();
    }

    private static void assertSame(VersionScheme scheme, String a, String b) {
        assertThat(scheme.compare(a, b)).as("%s: %s == %s", scheme.name(), a, b).isZero();
        assertThat(scheme.compare(b, a)).as("%s: %s == %s", scheme.name(), b, a).isZero();
    }

    /* ================================================================== */

    @Nested
    class SemVer {

        private final VersionScheme scheme = VersionSchemes.forEcosystem("npm");

        @ParameterizedTest(name = "{0} < {1}")
        @CsvSource({
                "1.0.0,        1.0.1",
                "1.0.9,        1.0.10",          // string comparison would invert this
                "1.9.0,        1.10.0",
                "1.0.0-alpha,  1.0.0",           // a pre-release ranks below its release
                "1.0.0-alpha,  1.0.0-alpha.1",   // shorter identifier list ranks lower
                "1.0.0-alpha.1,1.0.0-alpha.beta",
                "1.0.0-alpha.beta, 1.0.0-beta",
                "1.0.0-beta,   1.0.0-beta.2",
                "1.0.0-beta.2, 1.0.0-beta.11",   // numeric identifiers compare numerically
                "1.0.0-beta.11,1.0.0-rc.1",
                "1.0.0-rc.1,   1.0.0",
                "4.17.20,      4.17.21",
                "1.2.3,        1.2.3.4",         // NuGet's fourth field ranks above three
                "1.0.0.beta1,  1.0.0",           // RubyGems spells its pre-releases with a dot
                "1.0.0.beta1,  1.0.0.beta2",
        })
        void orders(String lower, String higher) {
            assertBelow(scheme, lower, higher);
        }

        @Test
        void abbreviatedVersionsEqualTheirZeroPaddedForm() {
            assertSame(scheme, "1.0.0", "1.0");
            assertSame(scheme, "1.0.0", "1");
            assertSame(scheme, "2.0", "2.0.0.0");
        }

        @Test
        void buildMetadataDoesNotAffectPrecedence() {
            assertSame(scheme, "1.0.0+build.1", "1.0.0+build.999");
            assertSame(scheme, "1.0.0", "1.0.0+sha.5114f85");
        }

        @Test
        void aLeadingVIsIgnored() {
            assertSame(scheme, "v1.2.3", "1.2.3");
        }

        @Test
        void rangeEvaluationIsHalfOpenAtTheFixedVersion() {
            // The false positive the old engine produced: the fixed version is NOT affected.
            assertThat(scheme.inRange("4.17.20", "0", "4.17.21", null)).isTrue();
            assertThat(scheme.inRange("4.17.21", "0", "4.17.21", null)).isFalse();
            assertThat(scheme.inRange("4.17.22", "0", "4.17.21", null)).isFalse();
            // And the lower bound the old engine did not have at all.
            assertThat(scheme.inRange("3.0.0", "4.0.0", "4.17.21", null)).isFalse();
        }

        @Test
        void lastAffectedIsInclusiveWhereFixedIsExclusive() {
            assertThat(scheme.inRange("1.2.3", "1.0.0", null, "1.2.3")).isTrue();
            assertThat(scheme.inRange("1.2.4", "1.0.0", null, "1.2.3")).isFalse();
        }

        @Test
        void anIntroducedOnlyRangeHasNoUpperBound() {
            assertThat(scheme.inRange("99.0.0", "1.0.0", null, null)).isTrue();
            assertThat(scheme.inRange("0.9.0", "1.0.0", null, null)).isFalse();
        }
    }

    /* ================================================================== */

    @Nested
    class Pep440 {

        private final VersionScheme scheme = VersionSchemes.forEcosystem("PyPI");

        @ParameterizedTest(name = "{0} < {1}")
        @CsvSource({
                "1.0.dev1,   1.0a1",       // dev ranks below every pre-release
                "1.0a1,      1.0a2",
                "1.0a2,      1.0b1",
                "1.0b1,      1.0rc1",
                "1.0rc1,     1.0",         // pre-release below the release
                "1.0,        1.0.post1",   // POST-release ABOVE the release — nothing like SemVer
                "1.0.post1,  1.0.post2",
                "1.0.post1,  1.0.1",
                "1.0,        1.1",
                "1.9,        1.10",
                "2.0,        1!1.0",       // an epoch outranks everything without one
                "1!1.0,      2!0.1",
        })
        void orders(String lower, String higher) {
            assertBelow(scheme, lower, higher);
        }

        @Test
        void trailingZerosAreInsignificant() {
            assertSame(scheme, "1.0", "1.0.0");
            assertSame(scheme, "1", "1.0.0.0");
        }

        @Test
        void theSpecAliasesAreOneVersion() {
            assertSame(scheme, "1.0a1", "1.0.alpha.1");
            assertSame(scheme, "1.0b2", "1.0-beta2");
            assertSame(scheme, "1.0rc1", "1.0.c1");
            assertSame(scheme, "1.0rc1", "1.0preview1");
        }

        @Test
        void aLocalVersionRanksAboveThePlainOne() {
            assertBelow(scheme, "1.0", "1.0+ubuntu1");
        }

        @Test
        void aDjangoStyleRangeExcludesTheFixedRelease() {
            assertThat(scheme.inRange("3.2.4", "3.2", "3.2.5", null)).isTrue();
            assertThat(scheme.inRange("3.2.5", "3.2", "3.2.5", null)).isFalse();
            // A release candidate for the fix is still inside the affected range.
            assertThat(scheme.inRange("3.2.5rc1", "3.2", "3.2.5", null)).isTrue();
        }

        @Test
        void garbageDegradesInsteadOfThrowing() {
            assertThat(scheme.compare("not-a-version", "1.0")).isNotZero();
            assertThat(scheme.compare(null, "1.0")).isNegative();
        }
    }

    /* ================================================================== */

    @Nested
    class Maven {

        private final VersionScheme scheme = VersionSchemes.forEcosystem("Maven");

        @ParameterizedTest(name = "{0} < {1}")
        @CsvSource({
                "2.14.1,        2.15.0",
                "2.17.0,        2.17.1",
                "1.0-alpha,     1.0-beta",
                "1.0-beta,      1.0-milestone",
                "1.0-milestone, 1.0-rc1",
                "1.0-rc1,       1.0-SNAPSHOT",   // Maven's ranking, not intuition's
                "1.0-SNAPSHOT,  1.0",
                "1.0,           1.0-sp1",        // a service pack ranks above the release
                "1.0,           1.0.1",
                "1.9,           1.10",
                "2.0-beta9,     2.0",
        })
        void orders(String lower, String higher) {
            assertBelow(scheme, lower, higher);
        }

        @Test
        void abbreviatedVersionsEqualTheirZeroPaddedForm() {
            assertSame(scheme, "1.0", "1.0.0");
            assertSame(scheme, "1", "1.0");
            assertSame(scheme, "1.0", "1.0-final");
            assertSame(scheme, "1.0", "1.0-ga");
        }

        @Test
        void log4ShellRangeExcludesTheFixedRelease() {
            // CVE-2021-44228: affected [2.0-beta9, 2.15.0).
            assertThat(scheme.inRange("2.14.1", "2.0-beta9", "2.15.0", null)).isTrue();
            assertThat(scheme.inRange("2.15.0", "2.0-beta9", "2.15.0", null)).isFalse();
            assertThat(scheme.inRange("1.2.17", "2.0-beta9", "2.15.0", null)).isFalse();
        }
    }

    /* ================================================================== */

    @Nested
    class Go {

        private final VersionScheme scheme = VersionSchemes.forEcosystem("Go");

        @Test
        void theMandatoryVPrefixIsNotPartOfTheOrdering() {
            assertSame(scheme, "v1.7.3", "1.7.3");
            assertBelow(scheme, "v1.7.3", "v1.7.4");
            assertBelow(scheme, "1.7.3", "v1.7.4");
        }

        @Test
        void incompatibleIsBuildMetadataAndCarriesNoWeight() {
            assertSame(scheme, "v3.0.0+incompatible", "v3.0.0");
        }

        @Test
        void aPseudoVersionRanksBelowTheReleaseItPrecedes() {
            assertBelow(scheme, "v0.0.0-20191109021931-daa7c04131f5", "v0.0.1");
            assertBelow(scheme, "v1.2.3-20191109021931-daa7c04131f5", "v1.2.3");
        }

        @Test
        void twoPseudoVersionsOrderByTimestamp() {
            assertBelow(scheme,
                    "v0.0.0-20191109021931-daa7c04131f5",
                    "v0.0.0-20201109021931-aaa7c04131f5");
        }

        @Test
        void anOsvGoRangeWithoutThePrefixStillMatchesAPrefixedComponent() {
            // OSV writes Go ranges without the v; go.mod and most SBOM generators keep it.
            assertThat(scheme.inRange("v1.7.3", "1.6.0", "1.7.4", null)).isTrue();
            assertThat(scheme.inRange("v1.7.4", "1.6.0", "1.7.4", null)).isFalse();
        }
    }

    /* ================================================================== */

    @Nested
    class Generic {

        private final VersionScheme scheme = VersionSchemes.generic();

        @Test
        void theOldDottedNumericBehaviourIsPreserved() {
            // Exactly what util.Version did, for the inputs it accepted.
            assertBelow(scheme, "1.0", "1.1");
            assertBelow(scheme, "1.0.1", "1.0.10");
            assertBelow(scheme, "1.2", "1.10");
            assertSame(scheme, "1.0", "1.0.0");
            assertSame(scheme, "1", "1.0.0");
        }

        @Test
        void itNoLongerThrowsOnTheVersionsTheOldClassRejected() {
            // util.Version threw IllegalArgumentException for every one of these, and AlertService
            // caught it and fell back to string equality.
            assertThat(scheme.compare("1.1.1g", "1.1.1f")).isPositive();
            assertThat(scheme.compare("8u261", "8u251")).isPositive();
            assertThat(scheme.compare("", "1.0")).isNegative();
        }

        @Test
        void anOpenSslPatchLetterRanksAboveTheBareVersion() {
            // The CPE corpus convention, and the reason this scheme is not SemVer.
            assertBelow(scheme, "1.1.1", "1.1.1a");
            assertBelow(scheme, "1.1.1f", "1.1.1g");
        }

        @Test
        void aJavaUpdateStringOrdersNumericallyNotLexically() {
            assertBelow(scheme, "8u9", "8u10");
        }

        @Test
        void cpeRangeAttributesEvaluateAsAHalfOpenInterval() {
            // versionStartIncluding=1.1.1, versionEndExcluding=1.1.1k
            assertThat(scheme.inCpeRange("1.1.1f", "1.1.1", null, null, "1.1.1k")).isTrue();
            assertThat(scheme.inCpeRange("1.1.1", "1.1.1", null, null, "1.1.1k")).isTrue();
            assertThat(scheme.inCpeRange("1.1.1k", "1.1.1", null, null, "1.1.1k")).isFalse();
            assertThat(scheme.inCpeRange("1.1.0", "1.1.1", null, null, "1.1.1k")).isFalse();

            // versionStartExcluding / versionEndIncluding, the other two attributes.
            assertThat(scheme.inCpeRange("1.1.1", null, "1.1.1", "1.2", null)).isFalse();
            assertThat(scheme.inCpeRange("1.2", null, "1.1.1", "1.2", null)).isTrue();
        }

        @Test
        void aRangeWithNoBoundsAcceptsEverything() {
            assertThat(scheme.contains("anything", VersionRange.ALL)).isTrue();
            assertThat(scheme.contains(null, VersionRange.ALL)).isFalse();
        }
    }

    /* ================================================================== */

    @Nested
    class Factory {

        @Test
        void ecosystemNamesResolveCaseInsensitively() {
            assertThat(VersionSchemes.forEcosystem("PyPI").name()).isEqualTo("pep440");
            assertThat(VersionSchemes.forEcosystem("pypi").name()).isEqualTo("pep440");
            assertThat(VersionSchemes.forEcosystem("Maven").name()).isEqualTo("maven");
            assertThat(VersionSchemes.forEcosystem("crates.io").name()).isEqualTo("semver");
            assertThat(VersionSchemes.forEcosystem("Go").name()).isEqualTo("go");
        }

        @Test
        void aReleaseQualifiedDistroEcosystemResolvesOnItsPrefix() {
            // OSV writes "Alpine:v3.16" / "Debian:11"; neither has a scheme, but the lookup must not
            // be confused by the qualifier.
            assertThat(VersionSchemes.forEcosystem("Alpine:v3.16").name()).isEqualTo("generic");
        }

        @Test
        void anUnknownOrMissingEcosystemGetsTheTolerantFallback() {
            assertThat(VersionSchemes.forEcosystem("Wolfi").name()).isEqualTo("generic");
            assertThat(VersionSchemes.forEcosystem(null).name()).isEqualTo("generic");
            assertThat(VersionSchemes.forEcosystem("  ").name()).isEqualTo("generic");
            assertThat(VersionSchemes.isKnown("npm")).isTrue();
            assertThat(VersionSchemes.isKnown("Wolfi")).isFalse();
        }
    }

}
