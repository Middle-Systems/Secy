package net.jdesive.secy.lineage;

import net.jdesive.secy.lineage.model.GraphEdge;
import net.jdesive.secy.lineage.model.GraphNode;
import net.jdesive.secy.lineage.model.LineageGraphSnapshot;
import net.jdesive.secy.lineage.model.NodeRef;
import net.jdesive.secy.lineage.source.AssetComponentRow;
import net.jdesive.secy.lineage.source.AssetRow;
import net.jdesive.secy.lineage.source.ComponentRow;
import net.jdesive.secy.lineage.source.CompromiseFindingRow;
import net.jdesive.secy.lineage.source.DependencyEdgeRow;
import net.jdesive.secy.lineage.source.LineageSourceData;
import net.jdesive.secy.lineage.source.ProductRow;
import net.jdesive.secy.lineage.source.SbomRow;
import net.jdesive.secy.lineage.source.VulnerabilityAlertRow;
import net.jdesive.secy.lineage.source.VulnerabilityRow;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Turns one tenant's {@link LineageSourceData} into a {@link LineageGraphSnapshot} — pure,
 * deterministic, no Spring/JPA dependency (ROADMAP.md, M1d).
 *
 * <p>One private {@code addX} method per source row type is the additive seam for M1j/M2/M3: a
 * future milestone adds a new {@link NodeLabel}/{@link EdgeType} pair and one new method here,
 * never a rewrite of the methods already below. Do not add placeholder methods for entities that
 * do not exist yet (Repo, Build, Finding, ActionItem, Owner — see the M1d plan's scope table).
 */
public class LineagePlanner {

    public LineageGraphSnapshot plan(UUID tenantId, LineageSourceData data) {
        String tenantIdStr = tenantId.toString();

        List<GraphNode> nodes = new ArrayList<>();
        List<GraphEdge> edges = new ArrayList<>();

        Set<UUID> productIds = new HashSet<>();
        Map<UUID, NodeRef> sbomRefs = new HashMap<>();
        Map<UUID, NodeRef> componentRefs = new HashMap<>();
        Map<UUID, NodeRef> assetRefs = new HashMap<>();
        Map<UUID, NodeRef> assetComponentRefs = new HashMap<>();
        Map<String, VulnerabilityRow> vulnerabilityById = new HashMap<>();
        for (VulnerabilityRow row : data.vulnerabilities()) {
            vulnerabilityById.put(row.id(), row);
        }
        Set<String> emittedVulnerabilityIds = new HashSet<>();

        addProducts(data.products(), tenantIdStr, nodes, productIds);
        addSboms(data.sboms(), tenantIdStr, productIds, nodes, edges, sbomRefs);
        addComponents(data.components(), tenantIdStr, sbomRefs, nodes, edges, componentRefs);
        addDependencyEdges(data.dependencyEdges(), sbomRefs, componentRefs, edges);
        addAssets(data.assets(), tenantIdStr, productIds, nodes, edges, assetRefs);
        addAssetComponents(data.assetComponents(), tenantIdStr, assetRefs, nodes, edges, assetComponentRefs);
        addAlerts(data.alerts(), tenantIdStr, componentRefs, assetComponentRefs, vulnerabilityById,
                emittedVulnerabilityIds, nodes, edges);
        addCompromiseFindings(data.compromiseFindings(), tenantIdStr, componentRefs, assetComponentRefs,
                nodes, edges);

        nodes.sort(Comparator.<GraphNode, Integer>comparing(n -> n.label().ordinal())
                .thenComparing(GraphNode::key));
        edges.sort(Comparator.<GraphEdge, Integer>comparing(e -> e.type().ordinal())
                .thenComparing(e -> e.from().label().ordinal())
                .thenComparing(e -> e.from().key())
                .thenComparing(e -> e.to().label().ordinal())
                .thenComparing(e -> e.to().key()));

        return new LineageGraphSnapshot(tenantId, nodes, edges);
    }

    /* ------------------------------------------------------------------ */
    /* Products                                                           */
    /* ------------------------------------------------------------------ */

    private void addProducts(List<ProductRow> rows, String tenantIdStr, List<GraphNode> nodes,
                              Set<UUID> productIds) {
        for (ProductRow row : rows) {
            String key = row.id().toString();
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("tenant_id", tenantIdStr);
            props.put("pg_id", key);
            putIfPresent(props, "name", row.name());
            putIfPresent(props, "tag_value", row.tagValue());
            props.put("unassigned", row.unassigned());
            putIfPresent(props, "created_at", str(row.createdAt()));
            nodes.add(new GraphNode(NodeLabel.PRODUCT, key, props));
            productIds.add(row.id());
        }
    }

    /* ------------------------------------------------------------------ */
    /* SBOMs                                                              */
    /* ------------------------------------------------------------------ */

    private void addSboms(List<SbomRow> rows, String tenantIdStr, Set<UUID> productIds,
                           List<GraphNode> nodes, List<GraphEdge> edges, Map<UUID, NodeRef> sbomRefs) {
        for (SbomRow row : rows) {
            String key = row.id().toString();
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("tenant_id", tenantIdStr);
            props.put("pg_id", key);
            putIfPresent(props, "format", row.format());
            putIfPresent(props, "spec_version", row.specVersion());
            props.put("version", (long) row.version());
            putIfPresent(props, "product_version", row.productVersion());
            putIfPresent(props, "status", row.status());
            putIfPresent(props, "upload_date", str(row.uploadDate()));
            putIfPresent(props, "ingestion_source", str(row.ingestionSource()));
            putIfPresent(props, "source_connector_id", str(row.sourceConnectorId()));
            putIfPresent(props, "lifecycle_stage", str(row.lifecycleStage()));

            NodeRef ref = new NodeRef(NodeLabel.SBOM, key);
            nodes.add(new GraphNode(NodeLabel.SBOM, key, props));
            sbomRefs.put(row.id(), ref);

            if (row.productId() != null && productIds.contains(row.productId())) {
                NodeRef productRef = new NodeRef(NodeLabel.PRODUCT, row.productId().toString());
                edges.add(new GraphEdge(EdgeType.HAS_SBOM, productRef, ref));
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* SBOM components                                                    */
    /* ------------------------------------------------------------------ */

    private void addComponents(List<ComponentRow> rows, String tenantIdStr, Map<UUID, NodeRef> sbomRefs,
                                List<GraphNode> nodes, List<GraphEdge> edges, Map<UUID, NodeRef> componentRefs) {
        for (ComponentRow row : rows) {
            NodeRef sbomRef = sbomRefs.get(row.sbomId());
            if (sbomRef == null) {
                continue; // its SBOM was not included (inactive, or otherwise filtered upstream)
            }
            String key = row.id().toString();
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("tenant_id", tenantIdStr);
            props.put("pg_id", key);
            putIfPresent(props, "name", row.name());
            putIfPresent(props, "version", row.version());
            putIfPresent(props, "purl", row.purl());
            putIfPresent(props, "identity_key", row.identityKey());
            putIfPresent(props, "component_type", row.type());
            putIfPresent(props, "identity_confidence", str(row.identityConfidence()));

            NodeRef ref = new NodeRef(NodeLabel.COMPONENT, key);
            nodes.add(new GraphNode(NodeLabel.COMPONENT, key, props));
            componentRefs.put(row.id(), ref);
            edges.add(new GraphEdge(EdgeType.CONTAINS, sbomRef, ref));
        }
    }

    /* ------------------------------------------------------------------ */
    /* Dependency edges (M1l)                                             */
    /* ------------------------------------------------------------------ */

    /**
     * {@code Component -[:DEPENDS_ON]-> Component}, or {@code SBOM -[:DEPENDS_ON]-> Component} when
     * {@link DependencyEdgeRow#fromRoot()} is true (the root is not a lineage node). Either end
     * missing from this snapshot (its SBOM/component was not included — inactive, filtered upstream,
     * or the root itself has no outgoing-edge node to reuse) skips the row rather than producing a
     * dangling edge. The table's own unique constraint plus one root row per SBOM means no duplicate
     * edge is possible here.
     */
    private void addDependencyEdges(List<DependencyEdgeRow> rows, Map<UUID, NodeRef> sbomRefs,
                                     Map<UUID, NodeRef> componentRefs, List<GraphEdge> edges) {
        for (DependencyEdgeRow row : rows) {
            NodeRef to = componentRefs.get(row.dependsOnComponentId());
            if (to == null) {
                continue;
            }
            NodeRef from = row.fromRoot() ? sbomRefs.get(row.sbomId()) : componentRefs.get(row.componentId());
            if (from == null) {
                continue;
            }
            edges.add(new GraphEdge(EdgeType.DEPENDS_ON, from, to));
        }
    }

    /* ------------------------------------------------------------------ */
    /* Assets                                                             */
    /* ------------------------------------------------------------------ */

    private void addAssets(List<AssetRow> rows, String tenantIdStr, Set<UUID> productIds,
                            List<GraphNode> nodes, List<GraphEdge> edges, Map<UUID, NodeRef> assetRefs) {
        for (AssetRow row : rows) {
            String key = row.id().toString();
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("tenant_id", tenantIdStr);
            props.put("pg_id", key);
            putIfPresent(props, "asset_type", str(row.type()));
            putIfPresent(props, "name", row.name());
            putIfPresent(props, "status", row.status());
            putIfPresent(props, "scanner", row.scanner());
            putIfPresent(props, "last_scanned_at", str(row.lastScannedAt()));

            NodeRef ref = new NodeRef(NodeLabel.ASSET, key);
            nodes.add(new GraphNode(NodeLabel.ASSET, key, props));
            assetRefs.put(row.id(), ref);

            if (row.productId() != null && productIds.contains(row.productId())) {
                NodeRef productRef = new NodeRef(NodeLabel.PRODUCT, row.productId().toString());
                edges.add(new GraphEdge(EdgeType.HAS_ASSET, productRef, ref));
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* Asset components                                                   */
    /* ------------------------------------------------------------------ */

    private void addAssetComponents(List<AssetComponentRow> rows, String tenantIdStr,
                                     Map<UUID, NodeRef> assetRefs, List<GraphNode> nodes,
                                     List<GraphEdge> edges, Map<UUID, NodeRef> assetComponentRefs) {
        for (AssetComponentRow row : rows) {
            NodeRef assetRef = assetRefs.get(row.assetId());
            if (assetRef == null) {
                continue;
            }
            String key = row.id().toString();
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("tenant_id", tenantIdStr);
            props.put("pg_id", key);
            putIfPresent(props, "name", row.name());
            putIfPresent(props, "version", row.version());
            putIfPresent(props, "purl", row.purl());
            putIfPresent(props, "identity_key", row.identityKey());
            putIfPresent(props, "ecosystem", row.ecosystem());
            putIfPresent(props, "source", str(row.source()));

            NodeRef ref = new NodeRef(NodeLabel.ASSET_COMPONENT, key);
            nodes.add(new GraphNode(NodeLabel.ASSET_COMPONENT, key, props));
            assetComponentRefs.put(row.id(), ref);
            edges.add(new GraphEdge(EdgeType.CONTAINS, assetRef, ref));
        }
    }

    /* ------------------------------------------------------------------ */
    /* Vulnerability alerts (+ the Vulnerability nodes they reference)     */
    /* ------------------------------------------------------------------ */

    private void addAlerts(List<VulnerabilityAlertRow> rows, String tenantIdStr,
                            Map<UUID, NodeRef> componentRefs, Map<UUID, NodeRef> assetComponentRefs,
                            Map<String, VulnerabilityRow> vulnerabilityById, Set<String> emittedVulnerabilityIds,
                            List<GraphNode> nodes, List<GraphEdge> edges) {
        for (VulnerabilityAlertRow row : rows) {
            NodeRef ownerRef = resolveOwner(row.componentId(), row.assetComponentId(), componentRefs, assetComponentRefs);
            if (ownerRef == null) {
                continue; // its component/assetComponent was not included
            }
            String key = row.id().toString();
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("tenant_id", tenantIdStr);
            props.put("pg_id", key);
            putIfPresent(props, "cve_id", row.cveId());
            putIfPresent(props, "lifecycle_state", str(row.lifecycleState()));
            putIfPresent(props, "triage_state", str(row.triageState()));
            props.put("actionable", row.actionable());
            putIfPresent(props, "actionable_reason", str(row.actionableReason()));
            putIfPresent(props, "match_confidence", str(row.matchConfidence()));
            putIfPresent(props, "fix_state", str(row.fixState()));
            putIfPresent(props, "exploit_maturity", str(row.exploitMaturity()));
            putIfPresent(props, "cvss_score", row.cvssScore());
            putIfPresent(props, "epss_score", row.epssScore());
            putIfPresent(props, "kev_due_date", str(row.kevDueDate()));

            NodeRef alertRef = new NodeRef(NodeLabel.VULNERABILITY_ALERT, key);
            nodes.add(new GraphNode(NodeLabel.VULNERABILITY_ALERT, key, props));
            edges.add(new GraphEdge(EdgeType.HAS_ALERT, ownerRef, alertRef));

            if (row.cveId() != null) {
                if (emittedVulnerabilityIds.add(row.cveId())) {
                    VulnerabilityRow vuln = vulnerabilityById.get(row.cveId());
                    Map<String, Object> vulnProps = new LinkedHashMap<>();
                    vulnProps.put("tenant_id", tenantIdStr);
                    vulnProps.put("pg_id", row.cveId());
                    if (vuln != null) {
                        putIfPresent(vulnProps, "base_severity", vuln.baseSeverity());
                        vulnProps.put("cvss_score", vuln.cvssScore());
                        putIfPresent(vulnProps, "cve_status", str(vuln.cveStatus()));
                    }
                    nodes.add(new GraphNode(NodeLabel.VULNERABILITY, row.cveId(), vulnProps));
                }
                NodeRef vulnRef = new NodeRef(NodeLabel.VULNERABILITY, row.cveId());
                edges.add(new GraphEdge(EdgeType.ALERT_FOR, alertRef, vulnRef));
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* Compromise findings                                                */
    /* ------------------------------------------------------------------ */

    private void addCompromiseFindings(List<CompromiseFindingRow> rows, String tenantIdStr,
                                        Map<UUID, NodeRef> componentRefs, Map<UUID, NodeRef> assetComponentRefs,
                                        List<GraphNode> nodes, List<GraphEdge> edges) {
        for (CompromiseFindingRow row : rows) {
            NodeRef ownerRef = resolveOwner(row.componentId(), row.assetComponentId(), componentRefs, assetComponentRefs);
            if (ownerRef == null) {
                continue;
            }
            String key = row.id().toString();
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("tenant_id", tenantIdStr);
            props.put("pg_id", key);
            putIfPresent(props, "compromise_type", str(row.type()));
            putIfPresent(props, "confidence", str(row.confidence()));
            putIfPresent(props, "severity", row.severity());
            putIfPresent(props, "source", row.source());
            putIfPresent(props, "ioc_id", row.iocId());
            putIfPresent(props, "lifecycle_state", str(row.lifecycleState()));
            putIfPresent(props, "triage_state", str(row.triageState()));

            NodeRef findingRef = new NodeRef(NodeLabel.COMPROMISE_FINDING, key);
            nodes.add(new GraphNode(NodeLabel.COMPROMISE_FINDING, key, props));
            edges.add(new GraphEdge(EdgeType.HAS_COMPROMISE_FINDING, ownerRef, findingRef));
        }
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private static NodeRef resolveOwner(UUID componentId, UUID assetComponentId,
                                         Map<UUID, NodeRef> componentRefs, Map<UUID, NodeRef> assetComponentRefs) {
        if (componentId != null) {
            return componentRefs.get(componentId);
        }
        if (assetComponentId != null) {
            return assetComponentRefs.get(assetComponentId);
        }
        return null;
    }

    private static void putIfPresent(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    private static String str(Object value) {
        return value == null ? null : value.toString();
    }

    private static String str(Enum<?> value) {
        return value == null ? null : value.name();
    }

    private static String str(LocalDateTime value) {
        return value == null ? null : value.toString();
    }

    private static String str(LocalDate value) {
        return value == null ? null : value.toString();
    }

}
