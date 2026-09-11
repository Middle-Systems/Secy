package net.jdesive.secy.service.asset;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.asset.NormalizedScan;
import net.jdesive.secy.model.asset.ScanFormat;
import net.jdesive.secy.model.grype.GrypeReport;
import net.jdesive.secy.model.trivy.TrivyReport;
import org.springframework.stereotype.Service;

/**
 * Validates an uploaded scanner report and parses it into the one normalized model.
 *
 * <p>The {@code SbomParser} of the asset path, and deliberately the same contract: parsing is
 * <b>synchronous</b>, ahead of the job queue, so a document that can never succeed gets a plain
 * {@code 400} with nothing stored and nothing queued.
 *
 * <h2>Why it validates rather than sniffs</h2>
 *
 * <p>{@code SbomParser} has to sniff, because one endpoint serves two SBOM formats. The scan
 * endpoints are one per scanner ({@code /assets/scan/trivy}, {@code /assets/scan/grype}), so the
 * caller has already declared the format and the job here is to confirm the body agrees — posting
 * Grype output to the Trivy endpoint is a mistake worth a clear error, not something to silently
 * accept. The shapes are unmistakable: Trivy is {@code {SchemaVersion, ArtifactName, Results:[…]}},
 * Grype is {@code {matches:[…], source:{…}}}, and neither carries the other's markers.
 */
@Slf4j
@Service
public class AssetScanParser {

    private final ObjectMapper objectMapper;
    private final TrivyNormalizer trivyNormalizer;
    private final GrypeNormalizer grypeNormalizer;

    public AssetScanParser(ObjectMapper objectMapper, TrivyNormalizer trivyNormalizer,
                           GrypeNormalizer grypeNormalizer) {
        // Same ingest-hardening reasoning as SbomParser: both scanners add report fields every
        // release, and a report Secy could read 99% of must not be rejected because one new key
        // appeared. Copied so the application's shared mapper keeps its own configuration.
        this.objectMapper = objectMapper.copy().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        this.trivyNormalizer = trivyNormalizer;
        this.grypeNormalizer = grypeNormalizer;
    }

    /**
     * @throws UnsupportedScanFormatException when the body is not a JSON object, or is not the
     *                                        scanner report {@code format} names
     */
    public NormalizedScan parse(ScanFormat format, JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new UnsupportedScanFormatException(
                    "Request body must be a JSON object containing a " + format.label() + " scan report.");
        }
        return switch (format) {
            case TRIVY -> trivy(root);
            case GRYPE -> grype(root);
        };
    }

    private NormalizedScan trivy(JsonNode root) {
        if (looksLikeGrype(root)) {
            throw new UnsupportedScanFormatException(
                    "This looks like a Grype report (it has a 'matches' array). Post it to /assets/scan/grype.");
        }
        if (!looksLikeTrivy(root)) {
            throw new UnsupportedScanFormatException(
                    "Not a Trivy scan report: expected a top-level 'Results' array alongside 'ArtifactName' "
                            + "or 'SchemaVersion', as produced by `trivy image -f json`. Note that a "
                            + "`trivy config` / compliance report is a different document and is not accepted here.");
        }
        TrivyReport report;
        try {
            report = objectMapper.treeToValue(root, TrivyReport.class);
        } catch (Exception e) {
            throw new UnsupportedScanFormatException(
                    "Document looks like a Trivy report but could not be read as one: " + e.getMessage(), e);
        }
        return trivyNormalizer.normalize(report);
    }

    private NormalizedScan grype(JsonNode root) {
        if (looksLikeTrivy(root)) {
            throw new UnsupportedScanFormatException(
                    "This looks like a Trivy report (it has a 'Results' array). Post it to /assets/scan/trivy.");
        }
        if (!looksLikeGrype(root)) {
            throw new UnsupportedScanFormatException(
                    "Not a Grype scan report: expected a top-level 'matches' array, as produced by "
                            + "`grype <target> -o json`.");
        }
        GrypeReport report;
        try {
            report = objectMapper.treeToValue(root, GrypeReport.class);
        } catch (Exception e) {
            throw new UnsupportedScanFormatException(
                    "Document looks like a Grype report but could not be read as one: " + e.getMessage(), e);
        }
        return grypeNormalizer.normalize(report);
    }

    /**
     * {@code Results} plus one of the two artifact markers. {@code Results} alone is not enough: a
     * {@code trivy config} compliance report also has a {@code Results} array, with a completely
     * different element shape — and that document belongs to Phase 5's compliance path, not here.
     * Requiring {@code ArtifactName}/{@code SchemaVersion}, which a compliance report does not carry
     * (it has {@code ID}/{@code Title} instead), keeps the two apart.
     */
    private static boolean looksLikeTrivy(JsonNode root) {
        if (!root.path("Results").isArray()) {
            return false;
        }
        return root.path("ArtifactName").isTextual() || root.path("SchemaVersion").isNumber();
    }

    private static boolean looksLikeGrype(JsonNode root) {
        return root.path("matches").isArray();
    }

}
