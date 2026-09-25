package net.jdesive.secy.model.cbom;

import net.jdesive.secy.persistence.entity.CryptoAssetType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CryptoAssetIdentityTest {

    @Test
    void nameWinsAndIsLowerCasedAndSlugsPerType() {
        assertThat(CryptoAssetIdentity.keyOf(CryptoAssetType.ALGORITHM, "RSA-2048", null))
                .isEqualTo("cbom:algorithm:rsa-2048");
        assertThat(CryptoAssetIdentity.keyOf(CryptoAssetType.CERTIFICATE, "Example Cert", null))
                .isEqualTo("cbom:certificate:example cert");
        assertThat(CryptoAssetIdentity.keyOf(CryptoAssetType.PROTOCOL, "TLS 1.2", null))
                .isEqualTo("cbom:protocol:tls 1.2");
        assertThat(CryptoAssetIdentity.keyOf(CryptoAssetType.RELATED_CRYPTO_MATERIAL, "RSA Key", null))
                .isEqualTo("cbom:related-crypto-material:rsa key");
        assertThat(CryptoAssetIdentity.keyOf(CryptoAssetType.UNKNOWN, "Something", null))
                .isEqualTo("cbom:unknown:something");
    }

    @Test
    void oidFallbackWhenNoName() {
        assertThat(CryptoAssetIdentity.keyOf(CryptoAssetType.ALGORITHM, null, "1.2.840.113549.1.1.1"))
                .isEqualTo("cbom:algorithm:oid:1.2.840.113549.1.1.1");
        assertThat(CryptoAssetIdentity.keyOf(CryptoAssetType.ALGORITHM, "  ", "1.2.3"))
                .isEqualTo("cbom:algorithm:oid:1.2.3");
    }

    @Test
    void nullWhenNeitherNameNorOid() {
        assertThat(CryptoAssetIdentity.keyOf(CryptoAssetType.ALGORITHM, null, null)).isNull();
        assertThat(CryptoAssetIdentity.keyOf(CryptoAssetType.ALGORITHM, "  ", "  ")).isNull();
    }

    @Test
    void truncatesToMaxLength() {
        String longName = "a".repeat(600);
        String key = CryptoAssetIdentity.keyOf(CryptoAssetType.ALGORITHM, longName, null);
        assertThat(key).hasSize(CryptoAssetIdentity.MAX_LENGTH);
    }

}
