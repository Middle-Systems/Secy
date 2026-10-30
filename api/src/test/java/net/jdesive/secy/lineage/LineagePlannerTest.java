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
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.CveStatus;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.IdentityConfidence;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.TriageState;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class LineagePlannerTest {

    private final LineagePlanner planner = new LineagePlanner();

    private static final UUID TENANT = UUID.randomUUID();

    @Test
    void everyProductBecomesANodeWithTenantIdAndNullsOmitted() {
        UUID productId = UUID.randomUUID();
        ProductRow row = new ProductRow(productId, "Widget", null, false, LocalDateTime.of(2024, 1, 1, 0, 0));
        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(row), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of()));

        assertThat(snapshot.nodes()).hasSize(1);
        GraphNode node = snapshot.nodes().get(0);
        assertThat(node.label()).isEqualTo(NodeLabel.PRODUCT);
        assertThat(node.properties().get("tenant_id")).isEqualTo(TENANT.toString());
        assertThat(node.properties().get("pg_id")).isEqualTo(productId.toString());
        assertThat(node.properties().get("name")).isEqualTo("Widget");
        assertThat(node.properties()).doesNotContainKey("tag_value"); // null omitted
        assertThat(node.properties().get("unassigned")).isEqualTo(false);
        assertThat(node.properties().get("created_at")).isEqualTo("2024-01-01T00:00");
    }

    @Test
    void sbomWithNullProductIdGetsNoHasSbomEdge() {
        UUID sbomId = UUID.randomUUID();
        SbomRow sbom = sbomRow(sbomId, null);
        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(sbom), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of()));

        assertThat(snapshot.nodes()).hasSize(1);
        assertThat(snapshot.edges()).isEmpty();
    }

    @Test
    void sbomReferencingAProductNotInTheSnapshotGetsNoHasSbomEdge() {
        UUID sbomId = UUID.randomUUID();
        UUID unknownProductId = UUID.randomUUID();
        SbomRow sbom = sbomRow(sbomId, unknownProductId);
        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(sbom), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of()));

        assertThat(snapshot.edges()).isEmpty();
    }

    @Test
    void sbomWithAKnownProductGetsAHasSbomEdge() {
        UUID productId = UUID.randomUUID();
        UUID sbomId = UUID.randomUUID();
        ProductRow product = productRow(productId);
        SbomRow sbom = sbomRow(sbomId, productId);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(product), List.of(sbom), List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of()));

        assertThat(snapshot.edges()).containsExactly(
                new GraphEdge(EdgeType.HAS_SBOM, new NodeRef(NodeLabel.PRODUCT, productId.toString()),
                        new NodeRef(NodeLabel.SBOM, sbomId.toString())));
    }

    @Test
    void aComponentReferencingAnUnknownSbomIsDropped() {
        UUID danglingSbomId = UUID.randomUUID();
        ComponentRow component = componentRow(UUID.randomUUID(), danglingSbomId);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(), List.of(component),
                List.of(), List.of(), List.of(), List.of(), List.of()));

        assertThat(snapshot.nodes()).isEmpty();
        assertThat(snapshot.edges()).isEmpty();
    }

    @Test
    void aComponentOnAnIncludedSbomGetsAContainsEdge() {
        UUID sbomId = UUID.randomUUID();
        SbomRow sbom = sbomRow(sbomId, null);
        UUID componentId = UUID.randomUUID();
        ComponentRow component = componentRow(componentId, sbomId);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(sbom), List.of(component),
                List.of(), List.of(), List.of(), List.of(), List.of()));

        assertThat(snapshot.nodes()).hasSize(2);
        assertThat(snapshot.edges()).containsExactly(
                new GraphEdge(EdgeType.CONTAINS, new NodeRef(NodeLabel.SBOM, sbomId.toString()),
                        new NodeRef(NodeLabel.COMPONENT, componentId.toString())));
    }

    @Test
    void anAlertOnAMissingComponentIsDropped() {
        UUID missingComponentId = UUID.randomUUID();
        VulnerabilityAlertRow alert = alertRow(UUID.randomUUID(), missingComponentId, null, "CVE-2024-0001");

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(alert), List.of()));

        assertThat(snapshot.nodes()).isEmpty();
        assertThat(snapshot.edges()).isEmpty();
    }

    @Test
    void anAlertOnAnIncludedComponentGetsHasAlertAndAlertForEdges() {
        UUID sbomId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        UUID alertId = UUID.randomUUID();
        SbomRow sbom = sbomRow(sbomId, null);
        ComponentRow component = componentRow(componentId, sbomId);
        VulnerabilityAlertRow alert = alertRow(alertId, componentId, null, "CVE-2024-0001");
        VulnerabilityRow vuln = new VulnerabilityRow("CVE-2024-0001", "CRITICAL", 9.8, CveStatus.PUBLISHED);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(sbom), List.of(component),
                List.of(), List.of(), List.of(vuln), List.of(alert), List.of()));

        assertThat(snapshot.nodes()).extracting(GraphNode::label)
                .containsExactlyInAnyOrder(NodeLabel.SBOM, NodeLabel.COMPONENT, NodeLabel.VULNERABILITY_ALERT,
                        NodeLabel.VULNERABILITY);
        assertThat(snapshot.edges()).contains(
                new GraphEdge(EdgeType.HAS_ALERT, new NodeRef(NodeLabel.COMPONENT, componentId.toString()),
                        new NodeRef(NodeLabel.VULNERABILITY_ALERT, alertId.toString())),
                new GraphEdge(EdgeType.ALERT_FOR, new NodeRef(NodeLabel.VULNERABILITY_ALERT, alertId.toString()),
                        new NodeRef(NodeLabel.VULNERABILITY, "CVE-2024-0001")));
    }

    @Test
    void vulnerabilityNodesAreDeduplicatedAcrossAlertsWithinATenant() {
        UUID sbomId = UUID.randomUUID();
        SbomRow sbom = sbomRow(sbomId, null);
        UUID componentId1 = UUID.randomUUID();
        UUID componentId2 = UUID.randomUUID();
        ComponentRow c1 = componentRow(componentId1, sbomId);
        ComponentRow c2 = componentRow(componentId2, sbomId);
        VulnerabilityAlertRow alert1 = alertRow(UUID.randomUUID(), componentId1, null, "CVE-2024-9999");
        VulnerabilityAlertRow alert2 = alertRow(UUID.randomUUID(), componentId2, null, "CVE-2024-9999");
        VulnerabilityRow vuln = new VulnerabilityRow("CVE-2024-9999", "HIGH", 7.5, CveStatus.PUBLISHED);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(sbom), List.of(c1, c2),
                List.of(), List.of(), List.of(vuln), List.of(alert1, alert2), List.of()));

        long vulnNodeCount = snapshot.nodes().stream().filter(n -> n.label() == NodeLabel.VULNERABILITY).count();
        assertThat(vulnNodeCount).isEqualTo(1);
        long alertForEdgeCount = snapshot.edges().stream().filter(e -> e.type() == EdgeType.ALERT_FOR).count();
        assertThat(alertForEdgeCount).isEqualTo(2);
    }

    @Test
    void assetComponentsAndCompromiseFindingsFollowTheSamePattern() {
        UUID assetId = UUID.randomUUID();
        UUID assetComponentId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        AssetRow asset = new AssetRow(assetId, null, AssetType.CONTAINER_IMAGE, "acme/api:1.0", "COMPLETED",
                "TRIVY", null);
        AssetComponentRow assetComponent = new AssetComponentRow(assetComponentId, assetId, "openssl", "3.0.0",
                null, "name/openssl", null, AssetComponentSource.TRIVY);
        CompromiseFindingRow finding = new CompromiseFindingRow(findingId, null, assetComponentId,
                CompromiseType.MALICIOUS_PACKAGE, CompromiseConfidence.CONFIRMED, "CRITICAL", "OpenSSF",
                "MAL-1", AlertLifecycleState.ACTIVE, TriageState.OPEN);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(), List.of(),
                List.of(asset), List.of(assetComponent), List.of(), List.of(), List.of(finding)));

        assertThat(snapshot.edges()).containsExactlyInAnyOrder(
                new GraphEdge(EdgeType.CONTAINS, new NodeRef(NodeLabel.ASSET, assetId.toString()),
                        new NodeRef(NodeLabel.ASSET_COMPONENT, assetComponentId.toString())),
                new GraphEdge(EdgeType.HAS_COMPROMISE_FINDING,
                        new NodeRef(NodeLabel.ASSET_COMPONENT, assetComponentId.toString()),
                        new NodeRef(NodeLabel.COMPROMISE_FINDING, findingId.toString())));
    }

    @Test
    void aCompromiseFindingOnAMissingAssetComponentIsDropped() {
        CompromiseFindingRow finding = new CompromiseFindingRow(UUID.randomUUID(), null, UUID.randomUUID(),
                CompromiseType.MALWARE_HASH, CompromiseConfidence.LIKELY, "CRITICAL", "abuse.ch", "hash-1",
                AlertLifecycleState.ACTIVE, TriageState.OPEN);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(finding)));

        assertThat(snapshot.nodes()).isEmpty();
    }

    @Test
    void enumsNormalizeToTheirNameAndTimestampsToIsoStrings() {
        UUID sbomId = UUID.randomUUID();
        SbomRow sbom = new SbomRow(sbomId, null, "CycloneDX", "1.5", 1, "1.0.0", "COMPLETE",
                LocalDateTime.of(2024, 3, 4, 5, 6, 7), SbomIngestionSource.MANUAL_UPLOAD, null,
                SbomLifecycleStage.BUILD);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(sbom), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of()));

        GraphNode node = snapshot.nodes().get(0);
        assertThat(node.properties().get("ingestion_source")).isEqualTo("MANUAL_UPLOAD");
        assertThat(node.properties().get("lifecycle_stage")).isEqualTo("BUILD");
        assertThat(node.properties().get("upload_date")).isEqualTo("2024-03-04T05:06:07");
        assertThat(node.properties().get("version")).isEqualTo(1L);
    }

    @Test
    void planIsDeterministicUnderShuffledInput() {
        List<ProductRow> products = new ArrayList<>();
        List<SbomRow> sboms = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            UUID productId = UUID.randomUUID();
            products.add(productRow(productId));
            sboms.add(sbomRow(UUID.randomUUID(), productId));
        }
        LineageSourceData data = dataWith(products, sboms, List.of(), List.of(), List.of(), List.of(), List.of(),
                List.of());

        List<ProductRow> shuffledProducts = new ArrayList<>(products);
        Collections.shuffle(shuffledProducts);
        List<SbomRow> shuffledSboms = new ArrayList<>(sboms);
        Collections.shuffle(shuffledSboms);
        LineageSourceData shuffled = dataWith(shuffledProducts, shuffledSboms, List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of());

        assertThat(planner.plan(TENANT, data)).isEqualTo(planner.plan(TENANT, shuffled));
    }

    /* ------------------------------------------------------------------ */
    /* M1l: dependency edges                                              */
    /* ------------------------------------------------------------------ */

    @Test
    void componentToComponentDependencyEdgeAppears() {
        UUID sbomId = UUID.randomUUID();
        UUID aId = UUID.randomUUID();
        UUID bId = UUID.randomUUID();
        SbomRow sbom = sbomRow(sbomId, null);
        ComponentRow a = componentRow(aId, sbomId);
        ComponentRow b = componentRow(bId, sbomId);
        DependencyEdgeRow edge = new DependencyEdgeRow(sbomId, aId, bId, false);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(sbom), List.of(a, b),
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of(edge)));

        assertThat(snapshot.edges()).contains(
                new GraphEdge(EdgeType.DEPENDS_ON, new NodeRef(NodeLabel.COMPONENT, aId.toString()),
                        new NodeRef(NodeLabel.COMPONENT, bId.toString())));
    }

    @Test
    void fromRootRowGivesSbomToComponentDependsOnEdge() {
        UUID sbomId = UUID.randomUUID();
        UUID rootId = UUID.randomUUID();
        UUID aId = UUID.randomUUID();
        SbomRow sbom = sbomRow(sbomId, null);
        ComponentRow a = componentRow(aId, sbomId);
        DependencyEdgeRow edge = new DependencyEdgeRow(sbomId, rootId, aId, true);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(sbom), List.of(a),
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of(edge)));

        assertThat(snapshot.edges()).contains(
                new GraphEdge(EdgeType.DEPENDS_ON, new NodeRef(NodeLabel.SBOM, sbomId.toString()),
                        new NodeRef(NodeLabel.COMPONENT, aId.toString())));
    }

    @Test
    void edgeTargetingAMissingComponentIsSkippedWithoutDanglingEdgeException() {
        UUID sbomId = UUID.randomUUID();
        UUID aId = UUID.randomUUID();
        UUID missingComponentId = UUID.randomUUID();
        UUID missingSbomId = UUID.randomUUID();
        SbomRow sbom = sbomRow(sbomId, null);
        ComponentRow a = componentRow(aId, sbomId);
        // "to" not in this snapshot.
        DependencyEdgeRow edgeToMissing = new DependencyEdgeRow(sbomId, aId, missingComponentId, false);
        // fromRoot, but that SBOM is not in this snapshot either.
        DependencyEdgeRow edgeFromMissingRoot = new DependencyEdgeRow(missingSbomId, UUID.randomUUID(), aId, true);

        LineageGraphSnapshot snapshot = planner.plan(TENANT, dataWith(List.of(), List.of(sbom), List.of(a),
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of(edgeToMissing, edgeFromMissingRoot)));

        assertThat(snapshot.edges()).noneMatch(e -> e.type() == EdgeType.DEPENDS_ON);
    }

    @Test
    void noDependencyRowsLeavesExistingEdgeOrderUnchanged() {
        UUID sbomId = UUID.randomUUID();
        UUID productId = UUID.randomUUID();
        ProductRow product = productRow(productId);
        SbomRow sbom = sbomRow(sbomId, productId);
        UUID componentId = UUID.randomUUID();
        ComponentRow component = componentRow(componentId, sbomId);

        LineageGraphSnapshot withEmptyEdges = planner.plan(TENANT, dataWith(List.of(product), List.of(sbom),
                List.of(component), List.of(), List.of(), List.of(), List.of(), List.of(), List.of()));
        LineageGraphSnapshot withoutEdgesField = planner.plan(TENANT, dataWith(List.of(product), List.of(sbom),
                List.of(component), List.of(), List.of(), List.of(), List.of(), List.of()));

        assertThat(withEmptyEdges).isEqualTo(withoutEdgesField);
    }

    /* ------------------------------------------------------------------ */

    private static ProductRow productRow(UUID id) {
        return new ProductRow(id, "Product " + id, null, false, LocalDateTime.now());
    }

    private static SbomRow sbomRow(UUID id, UUID productId) {
        return new SbomRow(id, productId, "CycloneDX", "1.5", 1, "1.0.0", "COMPLETE", LocalDateTime.now(),
                SbomIngestionSource.MANUAL_UPLOAD, null, null);
    }

    private static ComponentRow componentRow(UUID id, UUID sbomId) {
        return new ComponentRow(id, sbomId, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21",
                "npm/lodash", "library", IdentityConfidence.CORROBORATED);
    }

    private static VulnerabilityAlertRow alertRow(UUID id, UUID componentId, UUID assetComponentId, String cveId) {
        return new VulnerabilityAlertRow(id, componentId, assetComponentId, cveId, AlertLifecycleState.ACTIVE,
                TriageState.OPEN, true, ActionableReason.KEV, MatchConfidence.EXACT, FixState.FIXED,
                ExploitMaturity.IN_THE_WILD, 9.8, 0.9, LocalDate.of(2024, 6, 1));
    }

    private static LineageSourceData dataWith(List<ProductRow> products, List<SbomRow> sboms,
                                               List<ComponentRow> components, List<AssetRow> assets,
                                               List<AssetComponentRow> assetComponents,
                                               List<VulnerabilityRow> vulnerabilities,
                                               List<VulnerabilityAlertRow> alerts,
                                               List<CompromiseFindingRow> compromiseFindings) {
        return dataWith(products, sboms, components, assets, assetComponents, vulnerabilities, alerts,
                compromiseFindings, List.of());
    }

    /** M1l overload — every other existing call site defaults {@code dependencyEdges} to empty. */
    private static LineageSourceData dataWith(List<ProductRow> products, List<SbomRow> sboms,
                                               List<ComponentRow> components, List<AssetRow> assets,
                                               List<AssetComponentRow> assetComponents,
                                               List<VulnerabilityRow> vulnerabilities,
                                               List<VulnerabilityAlertRow> alerts,
                                               List<CompromiseFindingRow> compromiseFindings,
                                               List<DependencyEdgeRow> dependencyEdges) {
        return new LineageSourceData(products, sboms, components, assets, assetComponents, vulnerabilities, alerts,
                compromiseFindings, dependencyEdges);
    }

}
