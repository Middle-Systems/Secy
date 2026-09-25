package net.jdesive.secy.service.vex;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import net.jdesive.secy.config.VexProperties;
import net.jdesive.secy.model.vex.ParsedVexDocument;
import net.jdesive.secy.service.vex.parser.VexFormatParsers;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Detects a VEX document's shape and dispatches to the matching pure parser — the single entry point
 * every caller (the controller, and every parser unit test) goes through.
 *
 * <p>Entirely synchronous and side-effect free: {@code POST /vex} calls this before anything is
 * persisted or queued, so a document that can never succeed is a plain {@code 400}/{@code 413} with
 * nothing left behind — the same discipline {@code SbomParser} established for SBOM uploads.
 */
@Component
public class VexDocumentParser {

    private static final String OPENVEX_NS_PREFIX = "https://openvex.dev/ns";

    private final VexProperties properties;

    private final JsonMapper objectMapper;

    public VexDocumentParser(VexProperties properties) {
        this.properties = properties;
        JsonFactory factory = JsonFactory.builder()
                .streamReadConstraints(StreamReadConstraints.builder()
                        .maxNestingDepth(properties.getMaxNestingDepth())
                        .maxStringLength(2_000_000)
                        .maxNumberLength(100)
                        .build())
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .build();
        this.objectMapper = JsonMapper.builder(factory)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .build();
    }

    /**
     * Parses and validates a VEX document. Never returns a document with zero statements or one
     * whose statement count exceeds {@code secy.vex.max-statements} — both are rejected.
     *
     * @throws VexDocumentRejectedException the body is not valid JSON, is not one of the three
     *                                      supported shapes, or the specific shape's own required
     *                                      structure is violated
     */
    public ParsedVexDocument parse(byte[] body) {
        JsonNode root = readTree(body);

        if (!root.isObject()) {
            throw new VexDocumentRejectedException(
                    "Request body must be a JSON object containing an OpenVEX, CSAF 2.0 VEX, or CycloneDX VEX document");
        }

        ParsedVexDocument parsed = detectAndDispatch(root);

        int total = parsed.statements().size() + parsed.skippedCount();
        if (total > properties.getMaxStatements()) {
            throw new VexDocumentRejectedException(
                    "Document declares " + total + " VEX statements, over the " + properties.getMaxStatements() + " limit");
        }
        if (parsed.statements().isEmpty()) {
            String sample = String.join("; ", parsed.warnings().subList(0, Math.min(5, parsed.warnings().size())));
            throw new VexDocumentRejectedException(
                    "Document contains no usable VEX statements" + (sample.isEmpty() ? "" : ": " + sample));
        }
        return parsed;
    }

    private ParsedVexDocument detectAndDispatch(JsonNode root) {
        JsonNode context = root.get("@context");
        if (context != null && context.isTextual() && context.asText().startsWith(OPENVEX_NS_PREFIX)) {
            return VexFormatParsers.openVex(root);
        }

        JsonNode document = root.get("document");
        if (document != null && document.isObject() && document.hasNonNull("csaf_version")) {
            String csafVersion = document.get("csaf_version").asText();
            if (!"2.0".equals(csafVersion)) {
                throw new VexDocumentRejectedException(
                        "Unsupported CSAF version '" + csafVersion + "' — only CSAF 2.0 is supported");
            }
            String category = document.hasNonNull("category") ? document.get("category").asText() : null;
            if (!"csaf_vex".equals(category) && !"csaf_security_advisory".equals(category)) {
                throw new VexDocumentRejectedException(
                        "Unsupported CSAF document.category '" + category + "' — expected csaf_vex or csaf_security_advisory");
            }
            return VexFormatParsers.csaf(root, properties);
        }

        JsonNode bomFormat = root.get("bomFormat");
        if (bomFormat != null && bomFormat.isTextual() && "CycloneDX".equalsIgnoreCase(bomFormat.asText())) {
            String specVersion = root.hasNonNull("specVersion") ? root.get("specVersion").asText() : "";
            if (!isAtLeast14(specVersion)) {
                throw new VexDocumentRejectedException(
                        "CycloneDX specVersion '" + specVersion + "' is below the minimum supported 1.4");
            }
            JsonNode vulnerabilities = root.get("vulnerabilities");
            if (vulnerabilities == null || !vulnerabilities.isArray() || vulnerabilities.isEmpty()) {
                throw new VexDocumentRejectedException(
                        "CycloneDX document contains no vulnerabilities[] — nothing to ingest as VEX. Upload SBOMs to POST /sbom.");
            }
            return VexFormatParsers.cycloneDx(root);
        }

        throw new VexDocumentRejectedException(
                "Unrecognised document shape — expected an OpenVEX, CSAF 2.0 VEX, or CycloneDX VEX document "
                        + "(an SPDX SBOM, for example, is none of these)");
    }

    private static boolean isAtLeast14(String specVersion) {
        String[] parts = specVersion.split("\\.");
        if (parts.length < 2) {
            return false;
        }
        try {
            int major = Integer.parseInt(parts[0].trim());
            int minor = Integer.parseInt(parts[1].trim());
            return major > 1 || (major == 1 && minor >= 4);
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private JsonNode readTree(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new VexDocumentRejectedException("Request body is not valid JSON: " + e.getMessage());
        } catch (RuntimeException e) {
            throw new VexDocumentRejectedException("Request body is not valid JSON: " + e.getMessage());
        }
    }

}
