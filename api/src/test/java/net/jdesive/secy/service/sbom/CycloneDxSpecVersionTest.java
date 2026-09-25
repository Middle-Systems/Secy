package net.jdesive.secy.service.sbom;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CycloneDxSpecVersionTest {

    @Test
    void versionsAtOrAboveTheFloorSupportCryptoAssets() {
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("1.6")).isTrue();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets(" 1.6 ")).isTrue();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("1.6.1")).isTrue();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("1.7")).isTrue();
    }

    @Test
    void versionsBelowTheFloorOrUnparseableDoNotSupportCryptoAssets() {
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("1.5")).isFalse();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("1.4")).isFalse();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("2.0")).isFalse();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("1")).isFalse();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("")).isFalse();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets(null)).isFalse();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("abc")).isFalse();
        assertThat(CycloneDxSpecVersion.supportsCryptoAssets("1.x")).isFalse();
    }

}
