package net.jdesive.secy.service.asset;

import net.jdesive.secy.model.component.ComponentIdentity;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PURL synthesis for scanners that do not emit one.
 *
 * <p>The reason this needs pinning: the synthesized PURL is what decides whether a scanned package
 * takes the OSV-primary path or the CPE fallback, and what its {@code identityKey} is. Get the
 * spelling wrong and a package found in an image silently correlates differently from the identical
 * component declared in an SBOM.
 */
class ScannerPurlsTest {

    @Test
    void trivyLanguagePackagesMapOntoTheirEcosystemsPurlType() {
        assertThat(ScannerPurls.forTrivy("npm", "lodash", "4.17.20")).isEqualTo("pkg:npm/lodash@4.17.20");
        assertThat(ScannerPurls.forTrivy("gobinary", "github.com/gorilla/mux", "v1.7.3"))
                .isEqualTo("pkg:golang/github.com/gorilla/mux@v1.7.3");
        assertThat(ScannerPurls.forTrivy("gemspec", "nokogiri", "1.13.0")).isEqualTo("pkg:gem/nokogiri@1.13.0");
        assertThat(ScannerPurls.forTrivy("pip", "django", "3.2")).isEqualTo("pkg:pypi/django@3.2");
    }

    @Test
    void aMavenPackageNameIsSplitOnTheGroupIdSeparator() {
        // Trivy spells a Maven package "groupId:artifactId"; a PURL wants them as namespace and name,
        // and OSV indexes the joined form — so this has to round-trip back through
        // ComponentIdentity to the same key an SBOM component would produce.
        String purl = ScannerPurls.forTrivy("jar", "org.apache.logging.log4j:log4j-core", "2.14.1");
        assertThat(purl).isEqualTo("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        assertThat(ComponentIdentity.keyOf(purl, null))
                .isEqualTo("maven/org.apache.logging.log4j:log4j-core");
    }

    @Test
    void aScopedNpmNameKeepsItsScopeAsANamespace() {
        String purl = ScannerPurls.forTrivy("npm", "@angular/core", "12.0.0");
        assertThat(ComponentIdentity.keyOf(purl, null)).isEqualTo("npm/@angular/core");
    }

    @Test
    void aMavenPackageWithNoGroupIdGetsNoPurlRatherThanHalfACoordinate() {
        assertThat(ScannerPurls.forTrivy("jar", "log4j-core", "2.14.1")).isNull();
    }

    @Test
    void anUnrecognisedTypeGetsNoPurlAndFallsToTheCpePath() {
        assertThat(ScannerPurls.forTrivy("conda", "numpy", "1.24.0")).isNull();
        assertThat(ScannerPurls.forTrivy(null, "whatever", "1.0")).isNull();
    }

    @Test
    void osPackageTypesAreRecognisedAcrossBothScannersVocabularies() {
        // Trivy names the distro; Grype/Syft names the package manager. Both must be caught, because
        // the identity-stability rule (no PURL for an OS package) depends on it.
        assertThat(ScannerPurls.isOsPackageType("alpine")).isTrue();
        assertThat(ScannerPurls.isOsPackageType("apk")).isTrue();
        assertThat(ScannerPurls.isOsPackageType("deb")).isTrue();
        assertThat(ScannerPurls.isOsPackageType("redhat")).isTrue();
        assertThat(ScannerPurls.isOsPackageType("npm")).isFalse();
        assertThat(ScannerPurls.isOsPackageType(null)).isFalse();
    }

    @Test
    void grypeArtifactTypesMapToo() {
        assertThat(ScannerPurls.forGrype("java-archive", "com.acme:widget", "1.0"))
                .isEqualTo("pkg:maven/com.acme/widget@1.0");
        assertThat(ScannerPurls.forGrype("go-module", "github.com/acme/lib", "v0.1.0"))
                .isEqualTo("pkg:golang/github.com/acme/lib@v0.1.0");
        assertThat(ScannerPurls.forGrype("python", "requests", "2.28.0")).isEqualTo("pkg:pypi/requests@2.28.0");
    }

}
