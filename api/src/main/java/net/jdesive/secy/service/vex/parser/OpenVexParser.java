package net.jdesive.secy.service.vex.parser;

import com.fasterxml.jackson.databind.JsonNode;
import net.jdesive.secy.model.vex.ParsedVexDocument;
import net.jdesive.secy.model.vex.ParsedVexStatement;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.service.vex.VexDocumentRejectedException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * OpenVEX — fully supported, v0.2.0 and the legacy v0.0.1 shape (see {@code VexDocumentParser} for
 * how the two are told apart and the mapping tables this follows).
 */
final class OpenVexParser {

    private OpenVexParser() {
    }

    static ParsedVexDocument parse(JsonNode root) {
        String contextText = root.path("@context").asText("");
        String specVersion = contextText.startsWith("https://openvex.dev/ns/")
                ? contextText.substring("https://openvex.dev/ns/".length())
                : "0.0.1";

        String documentKey = textOrNull(root, "@id");
        String documentVersion = root.hasNonNull("version") ? root.get("version").asText() : null;
        String author = textOrNull(root, "author");

        List<String> warnings = new ArrayList<>();
        LocalDateTime documentTimestamp = VexParsing.timestamp(
                firstNonBlank(textOrNull(root, "last_updated"), textOrNull(root, "timestamp")), warnings, "document");

        JsonNode statementsNode = root.get("statements");
        if (statementsNode == null || !statementsNode.isArray()) {
            throw new VexDocumentRejectedException("OpenVEX document's 'statements' must be an array");
        }

        List<ParsedVexStatement> emitted = new ArrayList<>();
        int skipped = 0;
        int ordinal = 0;

        for (JsonNode statement : statementsNode) {
            JsonNode vulnNode = statement.get("vulnerability");
            List<String> vulnCandidates = new ArrayList<>();
            if (vulnNode != null) {
                if (vulnNode.isTextual()) {
                    vulnCandidates.add(vulnNode.asText());
                } else if (vulnNode.isObject()) {
                    addIfText(vulnCandidates, vulnNode, "name");
                    addIfText(vulnCandidates, vulnNode, "@id");
                    JsonNode aliases = vulnNode.get("aliases");
                    if (aliases != null && aliases.isArray()) {
                        for (JsonNode alias : aliases) {
                            if (alias.isTextual()) {
                                vulnCandidates.add(alias.asText());
                            }
                        }
                    }
                }
            }
            List<String> cveIds = VexParsing.cveIds(vulnCandidates.toArray(new String[0]));
            if (cveIds.isEmpty()) {
                warnings.add("Skipped an OpenVEX statement with no CVE id in 'vulnerability'");
                skipped++;
                continue;
            }
            String aliasesJoined = aliasesExcluding(vulnCandidates, cveIds);

            String rawStatus = textOrNull(statement, "status");
            VexStatus status = mapStatus(rawStatus);
            if (status == null) {
                warnings.add("Skipped an OpenVEX statement with unrecognised status '" + rawStatus + "'");
                skipped += cveIds.size();
                continue;
            }

            String rawJustification = textOrNull(statement, "justification");
            var justification = VexParsing.openVexJustification(rawJustification);
            String impactStatement = textOrNull(statement, "impact_statement");
            String actionStatement = textOrNull(statement, "action_statement");

            if (VexParsing.isReasonlessNotAffected(status, justification, rawJustification, impactStatement)) {
                warnings.add("Skipped a reasonless not_affected OpenVEX statement (no justification, "
                        + "no impact_statement) for " + String.join(",", cveIds));
                skipped += cveIds.size();
                continue;
            }

            LocalDateTime statementTimestamp = VexParsing.timestamp(
                    firstNonBlank(textOrNull(statement, "last_updated"), textOrNull(statement, "timestamp")),
                    warnings, "statement");

            List<Target> targets = targetsOf(statement, warnings);

            for (String cveId : cveIds) {
                for (Target target : targets) {
                    emitted.add(new ParsedVexStatement(
                            cveId, aliasesJoined == null ? List.of() : List.of(aliasesJoined.split(",")),
                            status, rawStatus, justification, rawJustification, impactStatement, actionStatement,
                            target.productRef, target.purlTarget.targetPurl(), target.targetCpe,
                            target.purlTarget.matchVersion(), statementTimestamp, ordinal++));
                }
            }
        }

        return new ParsedVexDocument(VexDocumentFormat.OPENVEX, specVersion, documentKey, documentVersion, author,
                documentTimestamp, emitted, warnings, skipped);
    }

    private record Target(String productRef, VexParsing.PurlTarget purlTarget, String targetCpe) {
    }

    private static List<Target> targetsOf(JsonNode statement, List<String> warnings) {
        List<Target> targets = new ArrayList<>();
        JsonNode products = statement.get("products");
        if (products == null || !products.isArray() || products.isEmpty()) {
            warnings.add("Skipped an OpenVEX statement with no 'products'");
            return targets;
        }
        for (JsonNode product : products) {
            if (product.isTextual()) {
                String raw = product.asText();
                targets.add(new Target(raw, VexParsing.purlTarget(raw), null));
                if (VexParsing.purlTarget(raw).matchKey() == null) {
                    warnings.add("OpenVEX product '" + raw + "' has no usable PURL — stored unmatchable");
                }
                continue;
            }
            if (!product.isObject()) {
                continue;
            }
            String productId = textOrNull(product, "@id");
            JsonNode identifiers = product.get("identifiers");
            String purl = identifiers == null ? null : textOrNull(identifiers, "purl");
            String cpe23 = identifiers == null ? null : textOrNull(identifiers, "cpe23");
            String cpe22 = identifiers == null ? null : textOrNull(identifiers, "cpe22");
            String cpe = cpe23 != null ? cpe23 : cpe22;

            JsonNode subcomponents = product.get("subcomponents");
            if (subcomponents != null && subcomponents.isArray() && !subcomponents.isEmpty()) {
                for (JsonNode sub : subcomponents) {
                    String subId = textOrNull(sub, "@id");
                    JsonNode subIdentifiers = sub.get("identifiers");
                    String subPurl = subIdentifiers == null ? null : textOrNull(subIdentifiers, "purl");
                    String candidate = subPurl != null ? subPurl : (subId != null && subId.startsWith("pkg:") ? subId : null);
                    String productRef = (productId == null ? "" : productId) + " > " + (subId == null ? "" : subId);
                    VexParsing.PurlTarget resolved = candidate == null
                            ? VexParsing.PurlTarget.UNMATCHABLE : VexParsing.purlTarget(candidate);
                    if (resolved.matchKey() == null) {
                        warnings.add("OpenVEX subcomponent '" + productRef + "' has no usable PURL — stored unmatchable");
                    }
                    String subCpe = subIdentifiers == null ? null : firstNonBlank(
                            textOrNull(subIdentifiers, "cpe23"), textOrNull(subIdentifiers, "cpe22"));
                    targets.add(new Target(productRef, resolved, subCpe));
                }
            } else {
                String candidate = purl != null ? purl : (productId != null && productId.startsWith("pkg:") ? productId : null);
                VexParsing.PurlTarget resolved = candidate == null
                        ? VexParsing.PurlTarget.UNMATCHABLE : VexParsing.purlTarget(candidate);
                if (resolved.matchKey() == null) {
                    warnings.add("OpenVEX product '" + productId + "' has no usable PURL — stored unmatchable");
                }
                targets.add(new Target(productId, resolved, cpe));
            }
        }
        return targets;
    }

    private static VexStatus mapStatus(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "not_affected" -> VexStatus.NOT_AFFECTED;
            case "affected" -> VexStatus.AFFECTED;
            case "fixed" -> VexStatus.FIXED;
            case "under_investigation" -> VexStatus.UNDER_INVESTIGATION;
            default -> null;
        };
    }

    private static void addIfText(List<String> target, JsonNode node, String field) {
        String value = textOrNull(node, field);
        if (value != null) {
            target.add(value);
        }
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

    private static String textOrNull(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static String firstNonBlank(String a, String b) {
        return a != null && !a.isBlank() ? a : b;
    }

}
