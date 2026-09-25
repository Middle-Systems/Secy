package net.jdesive.secy.service.vex.parser;

import com.fasterxml.jackson.databind.JsonNode;
import net.jdesive.secy.model.vex.ParsedVexDocument;
import net.jdesive.secy.model.vex.ParsedVexStatement;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.service.vex.VexDocumentRejectedException;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * CycloneDX VEX — fully supported, standalone or embedded in a full SBOM, spec 1.4-1.6 (see
 * {@code VexDocumentParser} for the shape/version check and {@code POST /vex}'s embedded-document
 * note).
 */
final class CycloneDxVexParser {

    /** Recursion cap over {@code components[].components[]} while indexing bom-refs — not configurable. */
    private static final int MAX_COMPONENT_DEPTH = 32;

    private CycloneDxVexParser() {
    }

    static ParsedVexDocument parse(JsonNode root) {
        String specVersion = textOrNull(root, "specVersion");
        String documentKey = textOrNull(root, "serialNumber");
        String documentVersion = root.hasNonNull("version") ? root.get("version").asText() : null;

        JsonNode metadata = root.path("metadata");
        String author = firstAuthor(metadata);
        List<String> warnings = new ArrayList<>();
        LocalDateTime documentTimestamp = VexParsing.timestamp(textOrNull(metadata, "timestamp"), warnings, "document");

        Map<String, String> bomRefIndex = new LinkedHashMap<>();
        indexComponent(metadata.get("component"), bomRefIndex, 0);
        JsonNode components = root.get("components");
        if (components != null && components.isArray()) {
            for (JsonNode component : components) {
                indexComponent(component, bomRefIndex, 0);
            }
        }

        JsonNode vulnerabilities = root.get("vulnerabilities");
        if (vulnerabilities == null || !vulnerabilities.isArray() || vulnerabilities.isEmpty()) {
            throw new VexDocumentRejectedException(
                    "CycloneDX document contains no vulnerabilities[] — nothing to ingest as VEX. Upload SBOMs to POST /sbom.");
        }

        List<ParsedVexStatement> emitted = new ArrayList<>();
        int skipped = 0;
        int ordinal = 0;

        for (JsonNode vuln : vulnerabilities) {
            List<String> candidates = new ArrayList<>();
            addIfText(candidates, vuln, "id");
            JsonNode references = vuln.get("references");
            if (references != null && references.isArray()) {
                for (JsonNode reference : references) {
                    addIfText(candidates, reference, "id");
                }
            }
            List<String> cveIds = VexParsing.cveIds(candidates.toArray(new String[0]));
            if (cveIds.isEmpty()) {
                warnings.add("Skipped a CycloneDX vulnerability with no CVE id in 'id' or 'references[].id'");
                skipped++;
                continue;
            }
            String aliasesJoined = aliasesExcluding(candidates, cveIds);

            JsonNode analysis = vuln.get("analysis");
            String rawState = analysis == null ? null : textOrNull(analysis, "state");
            if (analysis == null || rawState == null) {
                warnings.add("Skipped " + String.join(",", cveIds) + " — no analysis/analysis.state "
                        + "(a vulnerability listing, not a VEX assertion)");
                skipped += cveIds.size();
                continue;
            }

            String rawJustification = textOrNull(analysis, "justification");
            StatusMapping mapping = mapState(rawState, rawJustification);
            if (mapping == null) {
                warnings.add("Skipped " + String.join(",", cveIds) + " — unrecognised analysis.state '" + rawState + "'");
                skipped += cveIds.size();
                continue;
            }
            VexJustification justification = mapping.justification;
            String sourceJustification = mapping.sourceJustification;

            String impactStatement = textOrNull(analysis, "detail");
            String actionStatement = actionStatementOf(analysis);

            if (VexParsing.isReasonlessNotAffected(mapping.status, justification, sourceJustification, impactStatement)) {
                warnings.add("Skipped a reasonless not_affected CycloneDX analysis for " + String.join(",", cveIds));
                skipped += cveIds.size();
                continue;
            }

            LocalDateTime timestamp = VexParsing.timestamp(firstNonBlank(
                    textOrNull(analysis, "lastUpdated"), textOrNull(analysis, "firstIssued"),
                    textOrNull(vuln, "updated"), textOrNull(vuln, "published")), warnings, "vulnerability");

            JsonNode affectsNode = vuln.get("affects");
            if (affectsNode == null || !affectsNode.isArray() || affectsNode.isEmpty()) {
                warnings.add("Skipped " + String.join(",", cveIds) + " — no 'affects' targets");
                skipped += cveIds.size();
                continue;
            }

            for (JsonNode affect : affectsNode) {
                String ref = textOrNull(affect, "ref");
                VexParsing.PurlTarget purlTarget = resolveRef(ref, bomRefIndex, warnings);
                if (purlTarget.matchKey() == null) {
                    warnings.add("Unresolvable/unmatchable affects[].ref '" + ref + "'");
                }
                List<String> matchVersions = matchVersionsFor(affect, purlTarget, warnings);
                if (matchVersions.isEmpty()) {
                    skipped += cveIds.size();
                    continue;
                }
                for (String cveId : cveIds) {
                    for (String matchVersion : matchVersions) {
                        emitted.add(new ParsedVexStatement(
                                cveId, aliasesJoined == null ? List.of() : List.of(aliasesJoined.split(",")),
                                mapping.status, rawState, justification, sourceJustification, impactStatement,
                                actionStatement, ref, purlTarget.targetPurl(), null, matchVersion, timestamp, ordinal++));
                    }
                }
            }
        }

        return new ParsedVexDocument(VexDocumentFormat.CYCLONEDX, specVersion, documentKey, documentVersion, author,
                documentTimestamp, emitted, warnings, skipped);
    }

    /* ------------------------------------------------------------------ */

    private record StatusMapping(VexStatus status, VexJustification justification, String sourceJustification) {
    }

    private static StatusMapping mapState(String rawState, String rawJustification) {
        VexJustification justification = mapJustification(rawJustification);
        return switch (rawState.trim().toLowerCase(Locale.ROOT)) {
            case "not_affected" -> new StatusMapping(VexStatus.NOT_AFFECTED, justification, rawJustification);
            case "false_positive" -> new StatusMapping(VexStatus.NOT_AFFECTED, justification,
                    rawJustification != null && !rawJustification.isBlank() ? rawJustification : "false_positive");
            case "resolved", "resolved_with_pedigree" -> new StatusMapping(VexStatus.FIXED, justification, rawJustification);
            case "exploitable" -> new StatusMapping(VexStatus.AFFECTED, justification, rawJustification);
            case "in_triage" -> new StatusMapping(VexStatus.UNDER_INVESTIGATION, justification, rawJustification);
            default -> null;
        };
    }

    private static VexJustification mapJustification(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "code_not_present" -> VexJustification.VULNERABLE_CODE_NOT_PRESENT;
            case "code_not_reachable" -> VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH;
            case "requires_configuration" -> VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY;
            case "requires_dependency" -> VexJustification.COMPONENT_NOT_PRESENT;
            case "requires_environment" -> VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY;
            case "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter",
                    "protected_by_mitigating_control" -> VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
            default -> null;
        };
    }

    private static String actionStatementOf(JsonNode analysis) {
        String response = null;
        JsonNode responseNode = analysis.get("response");
        if (responseNode != null && responseNode.isArray() && !responseNode.isEmpty()) {
            List<String> parts = new ArrayList<>();
            for (JsonNode r : responseNode) {
                if (r.isTextual()) {
                    parts.add(r.asText());
                }
            }
            if (!parts.isEmpty()) {
                response = "response: " + String.join(", ", parts);
            }
        }
        return VexParsing.joinNonBlank("; ", response, textOrNull(analysis, "recommendation"), textOrNull(analysis, "workaround"));
    }

    /* ------------------------------------------------------------------ */
    /* bom-ref index                                                       */
    /* ------------------------------------------------------------------ */

    private static void indexComponent(JsonNode component, Map<String, String> index, int depth) {
        if (component == null || !component.isObject() || depth > MAX_COMPONENT_DEPTH) {
            return;
        }
        String bomRef = textOrNull(component, "bom-ref");
        if (bomRef != null) {
            index.put(bomRef, textOrNull(component, "purl"));
        }
        JsonNode nested = component.get("components");
        if (nested != null && nested.isArray()) {
            for (JsonNode child : nested) {
                indexComponent(child, index, depth + 1);
            }
        }
    }

    private static VexParsing.PurlTarget resolveRef(String ref, Map<String, String> bomRefIndex, List<String> warnings) {
        if (ref == null || ref.isBlank()) {
            return VexParsing.PurlTarget.UNMATCHABLE;
        }
        String trimmed = ref.trim();
        if (bomRefIndex.containsKey(trimmed)) {
            String purl = bomRefIndex.get(trimmed);
            return purl == null ? VexParsing.PurlTarget.UNMATCHABLE : VexParsing.purlTarget(purl);
        }
        if (trimmed.startsWith("urn:cdx:")) {
            int hash = trimmed.indexOf('#');
            if (hash >= 0 && hash + 1 < trimmed.length()) {
                String fragment = URLDecoder.decode(trimmed.substring(hash + 1), StandardCharsets.UTF_8);
                if (bomRefIndex.containsKey(fragment)) {
                    String purl = bomRefIndex.get(fragment);
                    return purl == null ? VexParsing.PurlTarget.UNMATCHABLE : VexParsing.purlTarget(purl);
                }
                if (fragment.startsWith("pkg:")) {
                    return VexParsing.purlTarget(fragment);
                }
            }
            return VexParsing.PurlTarget.UNMATCHABLE;
        }
        if (trimmed.startsWith("pkg:")) {
            return VexParsing.purlTarget(trimmed);
        }
        return VexParsing.PurlTarget.UNMATCHABLE;
    }

    /**
     * @return the {@code matchVersion} to emit per target, or empty if every {@code versions[]} entry
     *         was itself skipped (never falls back to "all versions" in that case)
     */
    private static List<String> matchVersionsFor(JsonNode affect, VexParsing.PurlTarget purlTarget, List<String> warnings) {
        JsonNode versionsNode = affect.get("versions");
        if (versionsNode == null || !versionsNode.isArray() || versionsNode.isEmpty()) {
            List<String> single = new ArrayList<>();
            single.add(purlTarget.matchVersion());
            return single;
        }
        List<String> result = new ArrayList<>();
        for (JsonNode v : versionsNode) {
            String range = textOrNull(v, "range");
            if (range != null && !range.isBlank()) {
                warnings.add("Skipped affects[].versions[] range entry — version ranges not supported in M1f: " + range);
                continue;
            }
            String status = textOrNull(v, "status");
            String exact = textOrNull(v, "version");
            if (exact == null) {
                continue;
            }
            if (status != null && !"affected".equalsIgnoreCase(status)) {
                warnings.add("Skipped affects[].versions[] entry with status '" + status + "' — not a VEX assertion");
                continue;
            }
            result.add(exact.trim());
        }
        return result;
    }

    /* ------------------------------------------------------------------ */

    private static String firstAuthor(JsonNode metadata) {
        JsonNode authors = metadata.get("authors");
        if (authors != null && authors.isArray() && !authors.isEmpty()) {
            String name = textOrNull(authors.get(0), "name");
            if (name != null) {
                return name;
            }
        }
        String supplier = textOrNull(metadata.get("supplier"), "name");
        if (supplier != null) {
            return supplier;
        }
        String manufacturer = textOrNull(metadata.get("manufacturer"), "name");
        if (manufacturer != null) {
            return manufacturer;
        }
        return textOrNull(metadata.get("manufacture"), "name");
    }

    private static String aliasesExcluding(List<String> candidates, List<String> primaryCveIds) {
        Set<String> primary = new LinkedHashSet<>();
        for (String id : primaryCveIds) {
            primary.add(id.toUpperCase(Locale.ROOT));
        }
        Set<String> rest = new LinkedHashSet<>();
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank() && !primary.contains(candidate.trim().toUpperCase(Locale.ROOT))) {
                rest.add(candidate.trim());
            }
        }
        return rest.isEmpty() ? null : String.join(",", rest);
    }

    private static void addIfText(List<String> target, JsonNode node, String field) {
        String value = textOrNull(node, field);
        if (value != null) {
            target.add(value);
        }
    }

    private static String textOrNull(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

}
