package net.jdesive.secy.service.vex.parser;

import com.fasterxml.jackson.databind.JsonNode;
import net.jdesive.secy.config.VexProperties;
import net.jdesive.secy.model.vex.ParsedVexDocument;
import net.jdesive.secy.model.vex.ParsedVexStatement;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.service.vex.VexDocumentRejectedException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CSAF 2.0 — a <b>deliberate subset</b>, not full CSAF (see {@code VexDocumentParser} for the
 * document-level {@code csaf_version}/{@code category} check, done before this is called, and the
 * M1f ROADMAP status note for the plain-language version of what follows).
 *
 * <h2>What this class implements</h2>
 *
 * <ul>
 *   <li>{@code product_tree.branches[]}, recursively, registering every node with a {@code product}
 *       by {@code product_id} (declared PURL/CPE, and whether the node is itself a
 *       {@code product_version_range}).</li>
 *   <li>{@code product_tree.full_product_names[]}, registered the same way.</li>
 *   <li>{@code product_tree.relationships[]} — <b>one hop only</b>: a relationship's
 *       {@code full_product_name.product_id} is registered using its own identification helper if it
 *       declares one, else by copying the {@code product_reference} (component side) entry that must
 *       already be registered from a branch or a full_product_name. A {@code product_reference} that
 *       points at another relationship's merged product (a two-hop chain), or at nothing registered at
 *       all, is left unresolved with a warning — see the "not implemented" list below.
 *       {@code relates_to_product_reference} (the platform side) is carried into {@code productRef}
 *       text only; it never scopes or narrows a match.</li>
 *   <li>{@code product_tree.product_groups[]}, expanded wherever a {@code flags}/{@code threats}/
 *       {@code remediations} entry names a {@code group_id} instead of (or alongside) explicit
 *       {@code product_ids}.</li>
 *   <li>Per {@code vulnerabilities[]}: {@code cve} (required — {@code ids[]} alone does not count),
 *       {@code product_status} bucket mapping with contradictory-bucket detection, {@code flags[]}
 *       justifications, {@code threats[]} with {@code category=="impact"}, and
 *       {@code remediations[]}.</li>
 * </ul>
 *
 * <h2>Explicitly NOT implemented — deliberately, not an oversight</h2>
 *
 * <p><b>TODO(post-M1f-csaf):</b> relationship chains beyond one hop (a {@code product_reference}
 * naming another relationship's merged product is left unresolved, not walked transitively).
 * <p><b>TODO(post-M1f-csaf):</b> platform scoping via {@code relates_to_product_reference} — recorded
 * in {@code productRef} text only, never used to narrow a match.
 * <p><b>TODO(post-M1f-csaf):</b> {@code product_version_range} / vers evaluation — a
 * {@code product_version_range} node is stored unmatchable, never evaluated against an observed
 * version.
 * <p><b>TODO(post-M1f-csaf):</b> CPE-based matching — a CPE-only product (no PURL) is stored
 * unmatchable; {@link net.jdesive.secy.persistence.entity.VexStatement#getTargetCpe()} is
 * informational only, exactly as for the other two formats.
 * <p><b>TODO(post-M1f-csaf):</b> hash, serial-number, model-number, SBOM-URL and
 * {@code x_generic_uris} identification helpers — only {@code purl}/{@code cpe} are read off
 * {@code product_identification_helper}.
 * <p><b>TODO(post-M1f-csaf):</b> {@code vulnerabilities[].ids[]}-only entries — a vulnerability with
 * no {@code cve} field is skipped, whatever {@code ids[]} says.
 * <p><b>TODO(post-M1f-csaf):</b> CSAF 2.1 and the {@code csaf_base} category — rejected at the
 * document-detection step in {@code VexDocumentParser}, before this class ever runs.
 * <p><b>TODO(post-M1f-csaf):</b> OpenPGP signature verification, and ROLIE/provider-metadata
 * discovery — this parser only ever sees a document body already fetched by {@code POST /vex}.
 * <p><b>TODO(post-M1f-csaf):</b> {@code notes[]} as a justification source — only {@code flags[]}
 * feeds {@link VexJustification}.
 * <p><b>TODO(post-M1f-csaf):</b> {@code scores[]} — CVSS vectors on the vulnerability are not read;
 * {@code vulnerability_alert.cvssScore} already comes from NVD.
 */
final class CsafVexParser {

    private CsafVexParser() {
    }

    private record CsafProduct(String name, String purl, String cpe, boolean versionRange) {
    }

    static ParsedVexDocument parse(JsonNode root, VexProperties properties) {
        JsonNode document = root.get("document");
        String author = textOrNull(document.get("publisher"), "name");
        String namespace = textOrNull(document.get("publisher"), "namespace");
        JsonNode tracking = document.get("tracking");
        String trackingId = tracking == null ? null : textOrNull(tracking, "id");
        String documentKey = (namespace == null ? "" : namespace) + "#" + (trackingId == null ? "" : trackingId);
        String documentVersion = tracking == null ? null : textOrNull(tracking, "version");

        List<String> warnings = new ArrayList<>();
        LocalDateTimeHolder documentTimestampHolder = new LocalDateTimeHolder();
        String releaseDate = tracking == null ? null : textOrNull(tracking, "current_release_date");
        documentTimestampHolder.value = VexParsing.timestamp(releaseDate, warnings, "document tracking.current_release_date");

        JsonNode productTree = root.get("product_tree");
        Map<String, CsafProduct> productMap = new LinkedHashMap<>();
        Map<String, List<String>> groupMap = new LinkedHashMap<>();
        Map<String, String> platformSuffixByProductId = new HashMap<>();
        Set<String> unresolvedProductIds = new HashSet<>();

        if (productTree != null) {
            walkBranches(productTree.get("branches"), productMap, 1, properties.getMaxBranchDepth());

            JsonNode fullProductNames = productTree.get("full_product_names");
            if (fullProductNames != null && fullProductNames.isArray()) {
                for (JsonNode fpn : fullProductNames) {
                    registerProduct(fpn, productMap, false);
                }
            }

            JsonNode groups = productTree.get("product_groups");
            if (groups != null && groups.isArray()) {
                for (JsonNode group : groups) {
                    String groupId = textOrNull(group, "group_id");
                    if (groupId == null) {
                        continue;
                    }
                    List<String> ids = new ArrayList<>();
                    JsonNode idsNode = group.get("product_ids");
                    if (idsNode != null && idsNode.isArray()) {
                        for (JsonNode id : idsNode) {
                            if (id.isTextual()) {
                                ids.add(id.asText());
                            }
                        }
                    }
                    groupMap.put(groupId, ids);
                }
            }

            JsonNode relationships = productTree.get("relationships");
            if (relationships != null && relationships.isArray()) {
                for (JsonNode rel : relationships) {
                    JsonNode fullProductName = rel.get("full_product_name");
                    if (fullProductName == null) {
                        continue;
                    }
                    String mergedId = textOrNull(fullProductName, "product_id");
                    if (mergedId == null) {
                        continue;
                    }
                    JsonNode helper = fullProductName.get("product_identification_helper");
                    boolean hasOwnHelper = helper != null && (helper.hasNonNull("purl") || helper.hasNonNull("cpe"));
                    if (hasOwnHelper) {
                        registerProduct(fullProductName, productMap, false);
                    } else {
                        String componentRef = textOrNull(rel, "product_reference");
                        CsafProduct component = componentRef == null ? null : productMap.get(componentRef);
                        if (component != null) {
                            productMap.put(mergedId, component);
                        } else {
                            warnings.add("Unresolvable CSAF relationship product_reference '" + componentRef
                                    + "' for merged product '" + mergedId + "' (relationship chains beyond one hop are not supported in M1f)");
                            unresolvedProductIds.add(mergedId);
                        }
                    }
                    String relatesTo = textOrNull(rel, "relates_to_product_reference");
                    if (relatesTo != null) {
                        platformSuffixByProductId.put(mergedId, relatesTo);
                    }
                }
            }
        }

        JsonNode vulnerabilities = root.get("vulnerabilities");
        List<ParsedVexStatement> emitted = new ArrayList<>();
        int skipped = 0;
        int ordinal = 0;

        if (vulnerabilities != null && vulnerabilities.isArray()) {
            for (JsonNode vuln : vulnerabilities) {
                String cveId = textOrNull(vuln, "cve");
                if (cveId == null || !cveId.matches("(?i)^CVE-\\d{4}-\\d{4,}$")) {
                    warnings.add("Skipped a CSAF vulnerability with no usable 'cve' field");
                    skipped++;
                    continue;
                }
                cveId = cveId.toUpperCase(java.util.Locale.ROOT);

                Map<String, LinkedHashMap<VexStatus, String>> statusesByProduct = statusesByProduct(vuln);
                Map<String, FlagInfo> justificationByProduct = justificationsByProduct(vuln, groupMap);
                Map<String, String> impactByProduct = joinedByProduct(vuln, "threats", "impact", groupMap);
                Map<String, String> actionByProduct = remediationsByProduct(vuln, groupMap);

                for (Map.Entry<String, LinkedHashMap<VexStatus, String>> entry : statusesByProduct.entrySet()) {
                    String productId = entry.getKey();
                    LinkedHashMap<VexStatus, String> statuses = entry.getValue();
                    if (statuses.size() > 1) {
                        warnings.add("Skipped product '" + productId + "' for " + cveId + " — contradictory product_status");
                        skipped++;
                        continue;
                    }
                    Map.Entry<VexStatus, String> only = statuses.entrySet().iterator().next();
                    VexStatus status = only.getKey();
                    String sourceStatus = only.getValue();

                    FlagInfo flag = justificationByProduct.get(productId);
                    VexJustification justification = flag == null ? null : flag.justification;
                    String sourceJustification = flag == null ? null : flag.rawLabel;
                    String impactStatement = impactByProduct.get(productId);
                    String actionStatement = actionByProduct.get(productId);

                    if (VexParsing.isReasonlessNotAffected(status, justification, sourceJustification, impactStatement)) {
                        warnings.add("Skipped a reasonless not_affected CSAF product_status for '" + productId + "' / " + cveId);
                        skipped++;
                        continue;
                    }

                    CsafProduct product = productMap.get(productId);
                    VexParsing.PurlTarget purlTarget;
                    String targetCpe = null;
                    if (product == null) {
                        if (!unresolvedProductIds.contains(productId)) {
                            warnings.add("Unknown CSAF product_id '" + productId + "' for " + cveId);
                        }
                        purlTarget = VexParsing.PurlTarget.UNMATCHABLE;
                    } else if (product.versionRange()) {
                        warnings.add("CSAF product '" + productId + "' is a product_version_range — not matched (M1f is exact-version only)");
                        purlTarget = VexParsing.PurlTarget.UNMATCHABLE;
                        targetCpe = product.cpe();
                    } else if (product.purl() == null) {
                        warnings.add("CSAF product '" + productId + "' has no usable PURL"
                                + (product.cpe() != null ? " (CPE-only; M1f is PURL-only)" : "") + " — stored unmatchable");
                        purlTarget = VexParsing.PurlTarget.UNMATCHABLE;
                        targetCpe = product.cpe();
                    } else {
                        purlTarget = VexParsing.purlTarget(product.purl());
                        targetCpe = product.cpe();
                    }

                    StringBuilder productRef = new StringBuilder(productId);
                    if (product != null && product.name() != null) {
                        productRef.append(' ').append(product.name());
                    }
                    String platformSuffix = platformSuffixByProductId.get(productId);
                    if (platformSuffix != null) {
                        productRef.append(" on ").append(platformSuffix);
                    }

                    emitted.add(new ParsedVexStatement(
                            cveId, List.of(), status, sourceStatus, justification, sourceJustification,
                            impactStatement, actionStatement, productRef.toString(), purlTarget.targetPurl(),
                            targetCpe, purlTarget.matchVersion(), null, ordinal++));
                }
            }
        }

        return new ParsedVexDocument(VexDocumentFormat.CSAF, "2.0", documentKey, documentVersion, author,
                documentTimestampHolder.value, emitted, warnings, skipped);
    }

    /* ------------------------------------------------------------------ */

    private static final class LocalDateTimeHolder {
        java.time.LocalDateTime value;
    }

    private record FlagInfo(VexJustification justification, String rawLabel) {
    }

    private static Map<String, LinkedHashMap<VexStatus, String>> statusesByProduct(JsonNode vuln) {
        Map<String, LinkedHashMap<VexStatus, String>> result = new LinkedHashMap<>();
        JsonNode productStatus = vuln.get("product_status");
        if (productStatus == null || !productStatus.isObject()) {
            return result;
        }
        Iterator<Map.Entry<String, JsonNode>> fields = productStatus.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            VexStatus mapped = bucketStatus(field.getKey());
            if (mapped == null) {
                continue;
            }
            JsonNode ids = field.getValue();
            if (ids == null || !ids.isArray()) {
                continue;
            }
            for (JsonNode idNode : ids) {
                if (!idNode.isTextual()) {
                    continue;
                }
                result.computeIfAbsent(idNode.asText(), k -> new LinkedHashMap<>())
                        .putIfAbsent(mapped, field.getKey());
            }
        }
        return result;
    }

    private static VexStatus bucketStatus(String bucket) {
        return switch (bucket) {
            case "known_not_affected" -> VexStatus.NOT_AFFECTED;
            case "known_affected", "first_affected", "last_affected" -> VexStatus.AFFECTED;
            case "fixed", "first_fixed" -> VexStatus.FIXED;
            case "under_investigation" -> VexStatus.UNDER_INVESTIGATION;
            default -> null; // "recommended" is a suggestion, not a status; anything else is unrecognised
        };
    }

    private static Map<String, FlagInfo> justificationsByProduct(JsonNode vuln, Map<String, List<String>> groupMap) {
        Map<String, FlagInfo> result = new LinkedHashMap<>();
        JsonNode flags = vuln.get("flags");
        if (flags == null || !flags.isArray()) {
            return result;
        }
        for (JsonNode flag : flags) {
            String label = textOrNull(flag, "label");
            VexJustification justification = VexParsing.openVexJustification(label);
            for (String productId : expandProductIds(flag, groupMap)) {
                result.putIfAbsent(productId, new FlagInfo(justification, label));
            }
        }
        return result;
    }

    private static Map<String, String> joinedByProduct(JsonNode vuln, String field, String requiredCategory,
                                                        Map<String, List<String>> groupMap) {
        Map<String, List<String>> byProduct = new LinkedHashMap<>();
        JsonNode entries = vuln.get(field);
        if (entries != null && entries.isArray()) {
            for (JsonNode entry : entries) {
                if (requiredCategory != null && !requiredCategory.equalsIgnoreCase(textOrNull(entry, "category"))) {
                    continue;
                }
                String details = textOrNull(entry, "details");
                if (details == null || details.isBlank()) {
                    continue;
                }
                for (String productId : expandProductIds(entry, groupMap)) {
                    byProduct.computeIfAbsent(productId, k -> new ArrayList<>()).add(details.trim());
                }
            }
        }
        Map<String, String> joined = new LinkedHashMap<>();
        byProduct.forEach((id, parts) -> joined.put(id, String.join("; ", parts)));
        return joined;
    }

    private static Map<String, String> remediationsByProduct(JsonNode vuln, Map<String, List<String>> groupMap) {
        Map<String, List<String>> byProduct = new LinkedHashMap<>();
        JsonNode remediations = vuln.get("remediations");
        if (remediations != null && remediations.isArray()) {
            for (JsonNode rem : remediations) {
                String details = textOrNull(rem, "details");
                if (details == null || details.isBlank()) {
                    continue;
                }
                String category = textOrNull(rem, "category");
                String text = (category == null ? "" : category + ": ") + details.trim();
                for (String productId : expandProductIds(rem, groupMap)) {
                    byProduct.computeIfAbsent(productId, k -> new ArrayList<>()).add(text);
                }
            }
        }
        Map<String, String> joined = new LinkedHashMap<>();
        byProduct.forEach((id, parts) -> joined.put(id, String.join("; ", parts)));
        return joined;
    }

    private static Set<String> expandProductIds(JsonNode entry, Map<String, List<String>> groupMap) {
        Set<String> ids = new LinkedHashSet<>();
        JsonNode productIds = entry.get("product_ids");
        if (productIds != null && productIds.isArray()) {
            for (JsonNode id : productIds) {
                if (id.isTextual()) {
                    ids.add(id.asText());
                }
            }
        }
        JsonNode groupIds = entry.get("group_ids");
        if (groupIds != null && groupIds.isArray()) {
            for (JsonNode groupId : groupIds) {
                if (groupId.isTextual()) {
                    List<String> expanded = groupMap.get(groupId.asText());
                    if (expanded != null) {
                        ids.addAll(expanded);
                    }
                }
            }
        }
        return ids;
    }

    /* ------------------------------------------------------------------ */
    /* product_tree                                                        */
    /* ------------------------------------------------------------------ */

    private static void walkBranches(JsonNode branches, Map<String, CsafProduct> productMap, int depth, int maxDepth) {
        if (branches == null || !branches.isArray()) {
            return;
        }
        if (depth > maxDepth) {
            throw new VexDocumentRejectedException("CSAF product_tree branch nesting exceeds " + maxDepth + " levels");
        }
        for (JsonNode branch : branches) {
            String category = textOrNull(branch, "category");
            JsonNode product = branch.get("product");
            if (product != null && product.isObject()) {
                registerProduct(product, productMap, "product_version_range".equals(category));
            }
            walkBranches(branch.get("branches"), productMap, depth + 1, maxDepth);
        }
    }

    private static void registerProduct(JsonNode product, Map<String, CsafProduct> productMap, boolean versionRange) {
        String productId = textOrNull(product, "product_id");
        if (productId == null) {
            return;
        }
        String name = textOrNull(product, "name");
        JsonNode helper = product.get("product_identification_helper");
        String purl = helper == null ? null : textOrNull(helper, "purl");
        String cpe = helper == null ? null : textOrNull(helper, "cpe");
        productMap.put(productId, new CsafProduct(name, purl, cpe, versionRange));
    }

    private static String textOrNull(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

}
