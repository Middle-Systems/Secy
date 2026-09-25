package net.jdesive.secy.service.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.cbom.NormalizedCryptoAsset;
import net.jdesive.secy.persistence.entity.CryptoAssetType;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * CycloneDX 1.6 {@code cryptoProperties} (a raw {@link JsonNode} — see
 * {@code CycloneDXComponent#getCryptoProperties}) → {@link NormalizedCryptoAsset} (M1g).
 *
 * <p>Pure, static, no Spring — unit-testable standalone, same bargain
 * {@code net.jdesive.secy.service.vex.VexFormatParsers} makes for tree-walking a VEX document.
 * <b>Never throws.</b> Real-world CBOM producers routinely emit shapes that disagree with the 1.6
 * schema (a pre-standard {@code certificationLevel} as a bare string instead of an array, a numeric
 * field as a numeric-looking string, and so on); every helper here degrades to {@code null}/empty
 * rather than raising, and the whole method additionally wraps itself in a last-resort
 * try/catch(RuntimeException) that degrades to {@code assetType = UNKNOWN} with nothing else, so one
 * unanticipated shape can never fail the whole SBOM upload.
 */
@Slf4j
public final class CryptoPropertiesExtractor {

    /** {@code sbom_component_crypto_asset.crypto_properties_json}. */
    private static final int MAX_SANITIZED_JSON_LENGTH = 16_384;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final NormalizedCryptoAsset UNKNOWN =
            new NormalizedCryptoAsset(CryptoAssetType.UNKNOWN, null, null, null, null, null, null, null);

    private CryptoPropertiesExtractor() {
    }

    public static NormalizedCryptoAsset extract(JsonNode cryptoProperties) {
        try {
            if (cryptoProperties == null || cryptoProperties.isNull() || !cryptoProperties.isObject()) {
                return UNKNOWN;
            }

            String declaredAssetType = text(cryptoProperties, "assetType");
            CryptoAssetType assetType = mapAssetType(declaredAssetType);
            String oid = text(cryptoProperties, "oid");

            NormalizedCryptoAsset.Algorithm algorithm = algorithm(object(cryptoProperties, "algorithmProperties"));
            NormalizedCryptoAsset.Certificate certificate = certificate(object(cryptoProperties, "certificateProperties"));
            NormalizedCryptoAsset.RelatedMaterial relatedMaterial =
                    relatedMaterial(object(cryptoProperties, "relatedCryptoMaterialProperties"));
            NormalizedCryptoAsset.Protocol protocol = protocol(object(cryptoProperties, "protocolProperties"));

            String sanitizedJson = sanitize(cryptoProperties);

            return new NormalizedCryptoAsset(assetType, declaredAssetType, oid, algorithm, certificate,
                    relatedMaterial, protocol, sanitizedJson);
        } catch (RuntimeException e) {
            log.warn("Failed to extract cryptoProperties, degrading to UNKNOWN: {}", e.getMessage(), e);
            return UNKNOWN;
        }
    }

    private static CryptoAssetType mapAssetType(String declared) {
        if (declared == null) {
            return CryptoAssetType.UNKNOWN;
        }
        return switch (declared.trim().toLowerCase(Locale.ROOT)) {
            case "algorithm" -> CryptoAssetType.ALGORITHM;
            case "certificate" -> CryptoAssetType.CERTIFICATE;
            case "protocol" -> CryptoAssetType.PROTOCOL;
            case "related-crypto-material", "related-material" -> CryptoAssetType.RELATED_CRYPTO_MATERIAL;
            default -> CryptoAssetType.UNKNOWN;
        };
    }

    private static NormalizedCryptoAsset.Algorithm algorithm(JsonNode node) {
        if (node == null) {
            return null;
        }
        String primitive = text(node, "primitive");
        return new NormalizedCryptoAsset.Algorithm(
                primitive == null ? null : primitive.toLowerCase(Locale.ROOT),
                text(node, "parameterSetIdentifier"),
                text(node, "curve"),
                text(node, "executionEnvironment"),
                text(node, "implementationPlatform"),
                stringList(node.get("certificationLevel")),
                text(node, "mode"),
                text(node, "padding"),
                stringList(node.get("cryptoFunctions")),
                intOrNull(node.get("classicalSecurityLevel")),
                intOrNull(node.get("nistQuantumSecurityLevel")));
    }

    private static NormalizedCryptoAsset.Certificate certificate(JsonNode node) {
        if (node == null) {
            return null;
        }
        return new NormalizedCryptoAsset.Certificate(
                text(node, "subjectName"),
                text(node, "issuerName"),
                dateOrNull(node.get("notValidBefore")),
                dateOrNull(node.get("notValidAfter")),
                text(node, "signatureAlgorithmRef"),
                text(node, "subjectPublicKeyRef"),
                text(node, "certificateFormat"),
                text(node, "certificateExtension"));
    }

    private static NormalizedCryptoAsset.RelatedMaterial relatedMaterial(JsonNode node) {
        if (node == null) {
            return null;
        }
        JsonNode securedBy = object(node, "securedBy");
        return new NormalizedCryptoAsset.RelatedMaterial(
                text(node, "type"),
                text(node, "id"),
                text(node, "state"),
                text(node, "algorithmRef"),
                dateOrNull(node.get("creationDate")),
                dateOrNull(node.get("activationDate")),
                dateOrNull(node.get("updateDate")),
                dateOrNull(node.get("expirationDate")),
                intOrNull(node.get("size")),
                text(node, "format"),
                securedBy == null ? null : text(securedBy, "mechanism"),
                securedBy == null ? null : text(securedBy, "algorithmRef"));
        // 'value' is deliberately never read here.
    }

    private static NormalizedCryptoAsset.Protocol protocol(JsonNode node) {
        if (node == null) {
            return null;
        }
        List<NormalizedCryptoAsset.CipherSuite> cipherSuites = cipherSuites(node.get("cipherSuites"));
        List<String> cryptoRefs = stringList(node.get("cryptoRefArray"));
        return new NormalizedCryptoAsset.Protocol(text(node, "type"), text(node, "version"), cipherSuites, cryptoRefs);
    }

    private static List<NormalizedCryptoAsset.CipherSuite> cipherSuites(JsonNode node) {
        if (node == null || !node.isArray() || node.isEmpty()) {
            return null;
        }
        List<NormalizedCryptoAsset.CipherSuite> out = new java.util.ArrayList<>();
        for (JsonNode entry : node) {
            if (entry == null || entry.isNull()) {
                continue;
            }
            if (entry.isObject()) {
                String name = text(entry, "name");
                List<String> algorithms = stringList(entry.get("algorithms"));
                if (name != null || algorithms != null) {
                    out.add(new NormalizedCryptoAsset.CipherSuite(name, algorithms));
                }
            } else if (entry.isTextual() || entry.isNumber()) {
                String name = entry.asText().trim();
                if (!name.isEmpty()) {
                    out.add(new NormalizedCryptoAsset.CipherSuite(name, null));
                }
            }
        }
        return out.isEmpty() ? null : List.copyOf(out);
    }

    private static String sanitize(JsonNode cryptoProperties) {
        try {
            JsonNode copy = cryptoProperties.deepCopy();
            if (copy.isObject()) {
                JsonNode relatedMaterial = copy.get("relatedCryptoMaterialProperties");
                if (relatedMaterial != null && relatedMaterial.isObject()) {
                    ((ObjectNode) relatedMaterial).remove("value");
                }
            }
            String json = MAPPER.writeValueAsString(copy);
            return json.length() > MAX_SANITIZED_JSON_LENGTH ? null : json;
        } catch (RuntimeException | com.fasterxml.jackson.core.JsonProcessingException e) {
            log.warn("Failed to sanitize cryptoProperties for storage: {}", e.getMessage());
            return null;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Node helpers                                                        */
    /* ------------------------------------------------------------------ */

    private static JsonNode object(JsonNode parent, String field) {
        JsonNode node = parent.get(field);
        return node != null && node.isObject() ? node : null;
    }

    /** Textual/numeric → trimmed {@code asText()}, blank → null; object/array/missing/null → null. */
    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || value.isObject() || value.isArray()) {
            return null;
        }
        String text = value.asText();
        if (text == null) {
            return null;
        }
        text = text.trim();
        return text.isEmpty() ? null : text;
    }

    /** An int node, or a numeric string, or null. */
    private static Integer intOrNull(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isInt() || node.isLong()) {
            return node.intValue();
        }
        if (node.isTextual()) {
            try {
                return Integer.parseInt(node.asText().trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        if (node.isNumber()) {
            return node.intValue();
        }
        return null;
    }

    /**
     * An array of scalars, or a single scalar treated as a one-element list, → a distinct list in
     * document order. Missing/null/object/empty → null.
     */
    private static List<String> stringList(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        Set<String> out = new LinkedHashSet<>();
        if (node.isArray()) {
            for (JsonNode entry : node) {
                if (entry != null && (entry.isTextual() || entry.isNumber() || entry.isBoolean())) {
                    String v = entry.asText().trim();
                    if (!v.isEmpty()) {
                        out.add(v);
                    }
                }
            }
        } else if (node.isTextual() || node.isNumber() || node.isBoolean()) {
            String v = node.asText().trim();
            if (!v.isEmpty()) {
                out.add(v);
            }
        } else {
            return null;
        }
        return out.isEmpty() ? null : List.copyOf(out);
    }

    /**
     * Tries {@link OffsetDateTime#parse}, then {@link LocalDateTime#parse}, then
     * {@link LocalDate#parse} + {@code atStartOfDay()}. Not textual, or none parse → null.
     */
    private static LocalDateTime dateOrNull(JsonNode node) {
        if (node == null || node.isNull() || !node.isTextual()) {
            return null;
        }
        String text = node.asText();
        if (text == null || text.isBlank()) {
            return null;
        }
        text = text.trim();
        try {
            return OffsetDateTime.parse(text).withOffsetSameInstant(ZoneOffset.UTC).toLocalDateTime();
        } catch (DateTimeParseException ignored) {
            // fall through
        }
        try {
            return LocalDateTime.parse(text);
        } catch (DateTimeParseException ignored) {
            // fall through
        }
        try {
            return LocalDate.parse(text).atStartOfDay();
        } catch (DateTimeParseException ignored) {
            return null;
        }
    }

}
