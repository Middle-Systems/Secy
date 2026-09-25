package net.jdesive.secy.service.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.cbom.NormalizedCryptoAsset;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.persistence.entity.CryptoAssetType;
import net.jdesive.secy.service.sbom.CycloneDXNormalizer;
import net.jdesive.secy.service.sbom.SbomParser;
import net.jdesive.secy.service.sbom.SpdxNormalizer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code CryptoPropertiesExtractor} exercised end to end through {@link SbomParser}, plus a couple of
 * direct-extractor edge cases that don't need a whole fixture file.
 */
class CryptoPropertiesParsingTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SbomParser parser =
            new SbomParser(new ObjectMapper(), new CycloneDXNormalizer(), new SpdxNormalizer());

    @Test
    void fullFixtureCapturesEveryFieldPerAssetType() throws IOException {
        List<NormalizedComponent> components = parse("cyclonedx-1.6-cbom-full.json").components();

        NormalizedComponent rsaAlgo = byBomRef(components, "rsa-algo");
        assertThat(rsaAlgo.crypto().assetType()).isEqualTo(CryptoAssetType.ALGORITHM);
        assertThat(rsaAlgo.crypto().declaredAssetType()).isEqualTo("algorithm");
        assertThat(rsaAlgo.crypto().oid()).isEqualTo("1.2.840.113549.1.1.1");
        NormalizedCryptoAsset.Algorithm rsaAlg = rsaAlgo.crypto().algorithm();
        assertThat(rsaAlg.primitive()).isEqualTo("pke");
        assertThat(rsaAlg.parameterSetIdentifier()).isEqualTo("2048");
        assertThat(rsaAlg.executionEnvironment()).isEqualTo("software-plain-ram");
        assertThat(rsaAlg.implementationPlatform()).isEqualTo("generic");
        assertThat(rsaAlg.certificationLevels()).containsExactly("none");
        assertThat(rsaAlg.padding()).isEqualTo("oaep");
        assertThat(rsaAlg.cryptoFunctions()).containsExactly("encrypt", "decrypt");
        assertThat(rsaAlg.classicalSecurityLevel()).isEqualTo(112);
        assertThat(rsaAlg.nistQuantumSecurityLevel()).isEqualTo(0);

        NormalizedComponent aes = byBomRef(components, "aes128gcm");
        assertThat(aes.crypto().algorithm().primitive()).isEqualTo("ae");
        assertThat(aes.crypto().algorithm().mode()).isEqualTo("gcm");
        assertThat(aes.crypto().algorithm().classicalSecurityLevel()).isEqualTo(128);

        NormalizedComponent mlkem = byBomRef(components, "mlkem768");
        assertThat(mlkem.crypto().oid()).isEqualTo("2.16.840.1.101.3.4.4.2");
        assertThat(mlkem.crypto().algorithm().primitive()).isEqualTo("kem");
        assertThat(mlkem.crypto().algorithm().nistQuantumSecurityLevel()).isEqualTo(3);

        NormalizedComponent cert = byBomRef(components, "cert1");
        assertThat(cert.crypto().assetType()).isEqualTo(CryptoAssetType.CERTIFICATE);
        NormalizedCryptoAsset.Certificate certificate = cert.crypto().certificate();
        assertThat(certificate.subjectName()).isEqualTo("CN=example.com");
        assertThat(certificate.issuerName()).isEqualTo("CN=Example CA");
        assertThat(certificate.notValidBefore()).isEqualTo(LocalDateTime.of(2024, 1, 1, 0, 0));
        assertThat(certificate.notValidAfter()).isEqualTo(LocalDateTime.of(2025, 1, 1, 0, 0));
        assertThat(certificate.signatureAlgorithmRef()).isEqualTo("sha256withrsa");
        assertThat(certificate.subjectPublicKeyRef()).isEqualTo("rsa-algo");
        assertThat(certificate.certificateFormat()).isEqualTo("X.509");
        assertThat(certificate.certificateExtension()).isEqualTo("crt");

        NormalizedComponent material = byBomRef(components, "pubkey-material");
        assertThat(material.crypto().assetType()).isEqualTo(CryptoAssetType.RELATED_CRYPTO_MATERIAL);
        NormalizedCryptoAsset.RelatedMaterial relatedMaterial = material.crypto().relatedMaterial();
        assertThat(relatedMaterial.type()).isEqualTo("private-key");
        assertThat(relatedMaterial.id()).isEqualTo("key-1");
        assertThat(relatedMaterial.state()).isEqualTo("active");
        assertThat(relatedMaterial.algorithmRef()).isEqualTo("rsa-algo");
        assertThat(relatedMaterial.creationDate()).isEqualTo(LocalDateTime.of(2024, 1, 1, 0, 0));
        assertThat(relatedMaterial.size()).isEqualTo(2048);
        assertThat(relatedMaterial.format()).isEqualTo("PEM");

        NormalizedComponent protocol = byBomRef(components, "tls-protocol");
        assertThat(protocol.crypto().assetType()).isEqualTo(CryptoAssetType.PROTOCOL);
        NormalizedCryptoAsset.Protocol proto = protocol.crypto().protocol();
        assertThat(proto.type()).isEqualTo("tls");
        assertThat(proto.version()).isEqualTo("1.2");
        assertThat(proto.cipherSuites()).hasSize(1);
        assertThat(proto.cipherSuites().get(0).name()).isEqualTo("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        assertThat(proto.cipherSuites().get(0).algorithmRefs()).containsExactly("rsa-algo");
        assertThat(proto.cryptoRefs()).containsExactly("aes128gcm");
    }

    @Test
    void relatedCryptoMaterialValueIsNeverCapturedInModelOrSanitizedJson() throws IOException {
        NormalizedComponent material = byBomRef(parse("cyclonedx-1.6-cbom-full.json").components(), "pubkey-material");

        assertThat(material.crypto().sanitizedJson()).doesNotContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC-FAKE");
        // RelatedMaterial has no accessor for 'value' at all -- the record simply doesn't carry it.
        assertThat(material.crypto().relatedMaterial().toString()).doesNotContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC-FAKE");
    }

    @Test
    void relatedMaterialAliasIsMapped() {
        JsonNode node = readTree("""
                { "assetType": "related-material",
                  "relatedCryptoMaterialProperties": { "type": "secret-key" } }
                """);
        NormalizedCryptoAsset asset = CryptoPropertiesExtractor.extract(node);
        assertThat(asset.assetType()).isEqualTo(CryptoAssetType.RELATED_CRYPTO_MATERIAL);
        assertThat(asset.declaredAssetType()).isEqualTo("related-material");
    }

    @Test
    void specVersion15SkipsExtractionButKeepsTheComponents() throws IOException {
        NormalizedSbom sbom = parse("cyclonedx-1.5-crypto-typed.json");

        assertThat(sbom.components()).hasSize(3);
        assertThat(byBomRef(sbom.components(), "rsa-algo").crypto()).isNull();
        assertThat(byBomRef(sbom.components(), "aes128gcm").crypto()).isNull();
        assertThat(sbom.cryptoAssetsIgnoredForSpecVersion()).isEqualTo(2);
    }

    @Test
    void malformedShapesDegradeLenientlyWithoutThrowing() throws IOException {
        List<NormalizedComponent> components = parse("cyclonedx-1.6-cbom-malformed.json").components();
        assertThat(components).hasSize(5);

        NormalizedComponent notAnObject = byBomRef(components, "not-an-object");
        assertThat(notAnObject.crypto().assetType()).isEqualTo(CryptoAssetType.UNKNOWN);

        NormalizedComponent arrayAlgo = byBomRef(components, "array-algorithm-properties");
        assertThat(arrayAlgo.crypto().assetType()).isEqualTo(CryptoAssetType.ALGORITHM);
        assertThat(arrayAlgo.crypto().algorithm()).isNull();

        NormalizedComponent scalarLists = byBomRef(components, "scalar-lists");
        NormalizedCryptoAsset.Algorithm alg = scalarLists.crypto().algorithm();
        assertThat(alg.primitive()).isEqualTo("signature");
        assertThat(alg.certificationLevels()).containsExactly("none");
        assertThat(alg.nistQuantumSecurityLevel()).isEqualTo(0);
        assertThat(alg.cryptoFunctions()).containsExactly("sign");

        NormalizedComponent badDateCert = byBomRef(components, "bad-date-cert");
        assertThat(badDateCert.crypto().certificate().notValidAfter()).isNull();

        NormalizedComponent scalarSuites = byBomRef(components, "scalar-cipher-suites");
        List<NormalizedCryptoAsset.CipherSuite> suites = scalarSuites.crypto().protocol().cipherSuites();
        assertThat(suites).hasSize(1);
        assertThat(suites.get(0).name()).isEqualTo("TLS_RSA_WITH_AES_128_CBC_SHA");
        assertThat(suites.get(0).algorithmRefs()).isNull();
    }

    @Test
    void cryptoPropertiesOnANonCryptoComponentIsIgnored() throws IOException {
        NormalizedComponent leftPad = byBomRef(parse("cyclonedx-1.6-cbom-full.json").components(), "left-pad");
        assertThat(leftPad.type()).isEqualTo("library");
        assertThat(leftPad.crypto()).isNull();
    }

    @Test
    void standaloneCbomParsesAndIsCryptoOnly() throws IOException {
        NormalizedSbom sbom = parse("cyclonedx-1.6-standalone-cbom.json");
        assertThat(sbom.rootComponent()).isNull();
        assertThat(sbom.components()).hasSize(2);
        assertThat(sbom.isCryptoOnly()).isTrue();
    }

    @Test
    void oversizedSanitizedJsonBecomesNull() {
        JsonNode node = readTree("""
                { "assetType": "certificate",
                  "certificateProperties": { "subjectName": "%s" } }
                """.formatted("a".repeat(20_000)));
        NormalizedCryptoAsset asset = CryptoPropertiesExtractor.extract(node);
        assertThat(asset.sanitizedJson()).isNull();
    }

    @Test
    void regressionExistingCycloneDxFixturesHaveNoCryptoAssets() throws IOException {
        for (String fixture : List.of("cyclonedx-mixed.json", "cyclonedx-identifiers.json",
                "cyclonedx-build-lifecycle.json")) {
            NormalizedSbom sbom = parser.parse(readSbomFixture(fixture));
            assertThat(sbom.components()).as(fixture).isNotEmpty();
            for (NormalizedComponent c : sbom.components()) {
                assertThat(c.crypto()).as("%s component %s", fixture, c.name()).isNull();
            }
            assertThat(sbom.cryptoAssetsIgnoredForSpecVersion()).as(fixture).isZero();
        }
    }

    /* ------------------------------------------------------------------ */

    private NormalizedSbom parse(String fixture) throws IOException {
        return parser.parse(readCbomFixture(fixture));
    }

    private JsonNode readCbomFixture(String fixture) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("cbom/" + fixture)) {
            assertThat(in).as("cbom/%s", fixture).isNotNull();
            return mapper.readTree(in);
        }
    }

    private JsonNode readSbomFixture(String fixture) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("sbom/" + fixture)) {
            assertThat(in).as("sbom/%s", fixture).isNotNull();
            return mapper.readTree(in);
        }
    }

    private JsonNode readTree(String json) {
        try {
            return mapper.readTree(json);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static NormalizedComponent byBomRef(List<NormalizedComponent> components, String bomRef) {
        Optional<NormalizedComponent> match = components.stream()
                .filter(c -> bomRef.equals(c.bomRef()))
                .findFirst();
        assertThat(match).as("component with bomRef %s", bomRef).isPresent();
        return match.get();
    }

}
