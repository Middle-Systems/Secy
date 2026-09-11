package net.jdesive.secy.service.sbom;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.cyclonedx.CycloneDXFile;
import net.jdesive.secy.model.spdx.SpdxDocument;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * Sniffs an uploaded document's format and parses it into the one normalized model.
 *
 * <h2>Detection</h2>
 *
 * <p>Both formats self-identify in a required top-level field, so detection needs no heuristics:
 *
 * <ul>
 *   <li>{@code "bomFormat": "CycloneDX"} → CycloneDX. Required by the CycloneDX JSON schema at every
 *       spec version, and its value is fixed, so it is both necessary and sufficient.</li>
 *   <li>{@code "spdxVersion": "SPDX-2.x"} → SPDX. Required by the SPDX JSON schema; the value
 *       carries the revision, which is then checked against {@link #SUPPORTED_SPDX_VERSIONS}.</li>
 *   <li>Neither → {@link UnsupportedSbomFormatException} → {@code 400}.</li>
 * </ul>
 *
 * <p>The check is on {@code bomFormat} first because a CycloneDX document never carries
 * {@code spdxVersion}, while an SBOM-conversion tool's output occasionally carries both.
 */
@Slf4j
@Service
public class SbomParser {

    /**
     * SPDX 2.2 and 2.3 share a JSON shape; {@link SpdxNormalizer} reads the union and tolerates the
     * 2.3-only fields being absent. 2.1 predates the official JSON serialisation and SPDX 3.x is a
     * different document model entirely, so both are rejected by name rather than mis-parsed.
     */
    static final Set<String> SUPPORTED_SPDX_VERSIONS = Set.of("SPDX-2.2", "SPDX-2.3");

    private final ObjectMapper objectMapper;
    private final CycloneDXNormalizer cycloneDXNormalizer;
    private final SpdxNormalizer spdxNormalizer;

    public SbomParser(ObjectMapper objectMapper,
                      CycloneDXNormalizer cycloneDXNormalizer,
                      SpdxNormalizer spdxNormalizer) {
        // Ingest hardening, stated here rather than inherited: SBOM producers add fields constantly
        // (CycloneDX 1.6 alone added several), and a document Secy could correlate 99% of must not be
        // rejected outright because one unrecognised key appeared. Copied so the application's shared
        // mapper keeps whatever configuration it has.
        this.objectMapper = objectMapper.copy().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        this.cycloneDXNormalizer = cycloneDXNormalizer;
        this.spdxNormalizer = spdxNormalizer;
    }

    /**
     * @throws UnsupportedSbomFormatException when the body is not a JSON object, identifies as
     *                                        neither format, declares an SPDX revision Secy does not
     *                                        read, or fails to bind
     */
    public NormalizedSbom parse(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new UnsupportedSbomFormatException(
                    "Request body must be a JSON object containing a CycloneDX or SPDX document.");
        }

        String bomFormat = text(root, "bomFormat");
        if (bomFormat != null) {
            if (!"CycloneDX".equalsIgnoreCase(bomFormat)) {
                throw new UnsupportedSbomFormatException(
                        "Unrecognised bomFormat '" + bomFormat + "'. Expected 'CycloneDX'.");
            }
            return cycloneDx(root);
        }

        String spdxVersion = text(root, "spdxVersion");
        if (spdxVersion != null) {
            if (!SUPPORTED_SPDX_VERSIONS.contains(spdxVersion.toUpperCase(java.util.Locale.ROOT))) {
                throw new UnsupportedSbomFormatException(
                        "Unsupported spdxVersion '" + spdxVersion + "'. Supported: SPDX-2.2, SPDX-2.3 (JSON).");
            }
            return spdx(root);
        }

        throw new UnsupportedSbomFormatException(
                "Unrecognised SBOM format: the document declares neither 'bomFormat' (CycloneDX) nor "
                        + "'spdxVersion' (SPDX). Supported formats: CycloneDX JSON, SPDX 2.2/2.3 JSON.");
    }

    private NormalizedSbom cycloneDx(JsonNode root) {
        CycloneDXFile file;
        try {
            file = objectMapper.treeToValue(root, CycloneDXFile.class);
        } catch (Exception e) {
            throw new UnsupportedSbomFormatException(
                    "Document declares bomFormat 'CycloneDX' but could not be read as one: " + e.getMessage(), e);
        }
        NormalizedSbom sbom = cycloneDXNormalizer.normalize(file);
        log.info("Parsed CycloneDX {} SBOM: {} components", sbom.specVersion(), sbom.components().size());
        return sbom;
    }

    private NormalizedSbom spdx(JsonNode root) {
        SpdxDocument document;
        try {
            document = objectMapper.treeToValue(root, SpdxDocument.class);
        } catch (Exception e) {
            throw new UnsupportedSbomFormatException(
                    "Document declares an spdxVersion but could not be read as SPDX JSON: " + e.getMessage(), e);
        }
        NormalizedSbom sbom = spdxNormalizer.normalize(document);
        log.info("Parsed {} SBOM: {} components", sbom.specVersion(), sbom.components().size());
        return sbom;
    }

    private static String text(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.isTextual()) {
            return null;
        }
        String value = node.asText().trim();
        return value.isEmpty() ? null : value;
    }

}
