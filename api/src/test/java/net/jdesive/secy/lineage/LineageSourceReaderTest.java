package net.jdesive.secy.lineage;

import net.jdesive.secy.lineage.model.GraphNode;
import net.jdesive.secy.lineage.model.LineageGraphSnapshot;
import net.jdesive.secy.persistence.AssetComponentRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMComponentRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.TenantRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.CveStatus;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link LineageSourceReader} + {@link LineagePlanner} together, against H2 — proves the scope
 * rules (active SBOMs only, root component excluded, present-in-last-scan-only asset components)
 * and tenant isolation for real, without needing Postgres/AGE (ROADMAP.md, M1d).
 */
@SpringBootTest
class LineageSourceReaderTest {

    @Autowired
    private LineageSourceReader reader;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private SBOMComponentRepository sbomComponentRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private AssetComponentRepository assetComponentRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private CompromiseFindingRepository findingRepository;

    private final LineagePlanner planner = new LineagePlanner();

    // Both before AND after: the H2 database is shared by every @SpringBootTest context in the
    // run (see TenancyFoundationTest's own cleanup note), and this test is the one class in the
    // suite that links a VulnerabilityAlert/CompromiseFinding straight to an AssetComponent --
    // leaving that behind after the last test method would break a later-running test class's own
    // (narrower) cleanup, e.g. one that deletes assets without first deleting alerts/findings.
    @BeforeEach
    void cleanUpBefore() {
        cleanUp();
    }

    @org.junit.jupiter.api.AfterEach
    void cleanUpAfter() {
        cleanUp();
    }

    private void cleanUp() {
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        vulnerabilityRepository.deleteAll();
    }

    @Test
    void planIncludesExactlyTheInScopeRowsAndKeepsTenantsIsolated() {
        UUID tenantA = Tenant.DEFAULT_TENANT_ID;
        Tenant tenantBEntity = new Tenant();
        tenantBEntity.setName("Tenant B");
        tenantBEntity.setSlug("tenant-b-" + UUID.randomUUID().toString().substring(0, 8));
        UUID tenantB = tenantRepository.save(tenantBEntity).getId();

        Fixture fixtureA = seedFixture(tenantA, null);
        Fixture fixtureB = seedFixture(tenantB, tenantB);

        LineageGraphSnapshot snapshotA = planner.plan(tenantA, reader.read(tenantA));

        // Node counts per label.
        assertThat(countByLabel(snapshotA, NodeLabel.PRODUCT)).isEqualTo(2); // product + unassigned bucket
        assertThat(countByLabel(snapshotA, NodeLabel.SBOM)).isEqualTo(2); // active SBOM + unassigned's SBOM (not the inactive one)
        assertThat(countByLabel(snapshotA, NodeLabel.COMPONENT)).isEqualTo(3); // compA, compB, compUnassigned -- root and inactive-SBOM's component excluded
        assertThat(countByLabel(snapshotA, NodeLabel.ASSET)).isEqualTo(1);
        assertThat(countByLabel(snapshotA, NodeLabel.ASSET_COMPONENT)).isEqualTo(1); // only the present one
        assertThat(countByLabel(snapshotA, NodeLabel.VULNERABILITY_ALERT)).isEqualTo(2);
        assertThat(countByLabel(snapshotA, NodeLabel.VULNERABILITY)).isEqualTo(2);
        assertThat(countByLabel(snapshotA, NodeLabel.COMPROMISE_FINDING)).isEqualTo(1);

        // Root component and the inactive SBOM's component never appear.
        Set<String> componentPgIds = pgIds(snapshotA, NodeLabel.COMPONENT);
        assertThat(componentPgIds).doesNotContain(fixtureA.rootComponent.getId().toString());
        assertThat(componentPgIds).doesNotContain(fixtureA.inactiveComponent.getId().toString());
        assertThat(componentPgIds).containsExactlyInAnyOrder(
                fixtureA.compA.getId().toString(), fixtureA.compB.getId().toString(),
                fixtureA.compUnassigned.getId().toString());

        // The not-present-in-last-scan asset component never appears.
        Set<String> assetComponentPgIds = pgIds(snapshotA, NodeLabel.ASSET_COMPONENT);
        assertThat(assetComponentPgIds).doesNotContain(fixtureA.acAbsent.getId().toString());
        assertThat(assetComponentPgIds).containsExactly(fixtureA.acPresent.getId().toString());

        // Zero tenant-B pg_ids leak into tenant A's plan.
        Set<String> allPgIdsInA = snapshotA.nodes().stream()
                .map(n -> String.valueOf(n.properties().get("pg_id")))
                .collect(java.util.stream.Collectors.toSet());
        assertThat(allPgIdsInA).doesNotContain(
                fixtureB.product.getId().toString(),
                fixtureB.activeSbom.getId().toString(),
                fixtureB.compA.getId().toString(),
                fixtureB.asset.getId().toString(),
                fixtureB.acPresent.getId().toString());

        // Calling plan twice gives equal snapshots.
        LineageGraphSnapshot snapshotAAgain = planner.plan(tenantA, reader.read(tenantA));
        assertThat(snapshotA).isEqualTo(snapshotAAgain);
    }

    private long countByLabel(LineageGraphSnapshot snapshot, NodeLabel label) {
        return snapshot.nodes().stream().filter(n -> n.label() == label).count();
    }

    private Set<String> pgIds(LineageGraphSnapshot snapshot, NodeLabel label) {
        return snapshot.nodes().stream()
                .filter(n -> n.label() == label)
                .map(GraphNode::key)
                .collect(java.util.stream.Collectors.toSet());
    }

    /** Seeds one tenant's worth of fixture data and returns the entities the test needs to reference. */
    private Fixture seedFixture(UUID tenantId, UUID explicitTenantId) {
        Fixture f = new Fixture();

        Product product = new Product();
        product.setName("P1-" + tenantId);
        applyTenant(product, explicitTenantId);
        f.product = productRepository.save(product);

        Product unassigned = new Product();
        unassigned.setName("Unassigned-" + tenantId);
        unassigned.setUnassigned(true);
        applyTenant(unassigned, explicitTenantId);
        f.unassignedProduct = productRepository.save(unassigned);

        // Active SBOM with a root component + 2 real components.
        SBOM activeSbom = new SBOM();
        activeSbom.setActive(true);
        activeSbom.setFormat("CycloneDX");
        activeSbom.setProduct(f.product);
        applyTenant(activeSbom, explicitTenantId);
        f.activeSbom = sbomRepository.save(activeSbom);

        SBOMComponent root = newComponent(f.activeSbom, "root-metadata", "pkg:generic/root@1.0");
        f.rootComponent = sbomComponentRepository.save(root);
        f.activeSbom.setComponent(f.rootComponent);
        sbomRepository.save(f.activeSbom);

        f.compA = sbomComponentRepository.save(newComponent(f.activeSbom, "lodash", "pkg:npm/lodash@4.17.21"));
        f.compB = sbomComponentRepository.save(newComponent(f.activeSbom, "left-pad", "pkg:npm/left-pad@1.0.0"));

        // Inactive SBOM -- excluded entirely, including its component.
        SBOM inactiveSbom = new SBOM();
        inactiveSbom.setActive(false);
        inactiveSbom.setFormat("CycloneDX");
        inactiveSbom.setProduct(f.product);
        applyTenant(inactiveSbom, explicitTenantId);
        f.inactiveSbom = sbomRepository.save(inactiveSbom);
        f.inactiveComponent = sbomComponentRepository.save(newComponent(f.inactiveSbom, "old-dep", "pkg:npm/old-dep@1.0.0"));

        // The Unassigned bucket's own active SBOM + component.
        SBOM unassignedSbom = new SBOM();
        unassignedSbom.setActive(true);
        unassignedSbom.setFormat("CycloneDX");
        unassignedSbom.setProduct(f.unassignedProduct);
        applyTenant(unassignedSbom, explicitTenantId);
        f.unassignedSbom = sbomRepository.save(unassignedSbom);
        f.compUnassigned = sbomComponentRepository.save(newComponent(f.unassignedSbom, "some-lib", "pkg:npm/some-lib@2.0.0"));

        // Vulnerability + alert on compA.
        Vulnerability v1 = vulnerabilityOrExisting("CVE-2024-" + Math.abs(tenantId.hashCode() % 9000 + 1000) + "-A");
        VulnerabilityAlert alert1 = new VulnerabilityAlert();
        alert1.setVulnerability(v1);
        alert1.setComponent(f.compA);
        alert1.setActionable(true);
        alert1.setActionableReason(ActionableReason.KEV);
        alert1.setMatchConfidence(MatchConfidence.EXACT);
        alert1.setFixState(FixState.FIXED);
        alert1.setExploitMaturity(ExploitMaturity.IN_THE_WILD);
        alert1.setCvssScore(9.8);
        alert1.setEpssScore(0.95);
        alert1.setTriageState(TriageState.OPEN);
        applyTenant(alert1, explicitTenantId);
        f.alertOnComponent = alertRepository.save(alert1);

        // Asset with 2 components, one absent from the last scan, and an alert on the present one.
        Asset asset = new Asset();
        asset.setType(AssetType.CONTAINER_IMAGE);
        asset.setName("acme/api-" + tenantId + ":1.0");
        asset.setProduct(f.product);
        asset.setStatus(Asset.STATUS_COMPLETED);
        asset.setCreatedAt(LocalDateTime.now());
        applyTenant(asset, explicitTenantId);
        f.asset = assetRepository.save(asset);

        AssetComponent acPresent = new AssetComponent();
        acPresent.setAsset(f.asset);
        acPresent.setName("openssl");
        acPresent.setVersion("3.0.0");
        acPresent.setPresentInLastScan(true);
        acPresent.setSource(AssetComponentSource.TRIVY);
        f.acPresent = assetComponentRepository.save(acPresent);

        AssetComponent acAbsent = new AssetComponent();
        acAbsent.setAsset(f.asset);
        acAbsent.setName("curl");
        acAbsent.setVersion("8.0.0");
        acAbsent.setPresentInLastScan(false);
        acAbsent.setSource(AssetComponentSource.TRIVY);
        f.acAbsent = assetComponentRepository.save(acAbsent);

        Vulnerability v2 = vulnerabilityOrExisting("CVE-2024-" + Math.abs(tenantId.hashCode() % 9000 + 1000) + "-B");
        VulnerabilityAlert alert2 = new VulnerabilityAlert();
        alert2.setVulnerability(v2);
        alert2.setAssetComponent(f.acPresent);
        alert2.setActionable(true);
        alert2.setActionableReason(ActionableReason.EPSS_HIGH);
        alert2.setMatchConfidence(MatchConfidence.RANGE);
        alert2.setFixState(FixState.UNKNOWN);
        alert2.setExploitMaturity(ExploitMaturity.NONE);
        alert2.setTriageState(TriageState.OPEN);
        applyTenant(alert2, explicitTenantId);
        f.alertOnAssetComponent = alertRepository.save(alert2);

        CompromiseFinding finding = new CompromiseFinding();
        finding.setComponent(f.compB);
        finding.setType(CompromiseType.MALICIOUS_PACKAGE);
        finding.setConfidence(CompromiseConfidence.CONFIRMED);
        finding.setSource("OpenSSF Malicious Packages");
        finding.setIocId("MAL-" + tenantId);
        finding.setMatchedOn("pkg:npm/left-pad@1.0.0");
        applyTenant(finding, explicitTenantId);
        f.finding = findingRepository.save(finding);

        return f;
    }

    private Vulnerability vulnerabilityOrExisting(String id) {
        return vulnerabilityRepository.findById(id).orElseGet(() -> {
            Vulnerability v = new Vulnerability();
            v.setId(id);
            v.setBaseSeverity("CRITICAL");
            v.setCvssScore(9.1);
            v.setCveStatus(CveStatus.PUBLISHED);
            return vulnerabilityRepository.save(v);
        });
    }

    private static SBOMComponent newComponent(SBOM sbom, String name, String purl) {
        SBOMComponent component = new SBOMComponent();
        component.setSbom(sbom);
        component.setName(name);
        component.setVersion("1.0.0");
        component.setPurl(purl);
        component.setType("library");
        // Unlike its sibling collections, SBOMComponent.vulnerabilityAlerts has no field
        // initializer -- leaving it null trips Hibernate's "collection with cascade=all-delete-
        // orphan was no longer referenced" check once the entity round-trips through a second
        // save() (as the root component does, below).
        component.setVulnerabilityAlerts(new java.util.ArrayList<>());
        return component;
    }

    private static void applyTenant(net.jdesive.secy.persistence.entity.TenantOwnedEntity entity, UUID explicitTenantId) {
        if (explicitTenantId != null) {
            entity.setTenantId(explicitTenantId);
        }
    }

    private static final class Fixture {
        Product product;
        Product unassignedProduct;
        SBOM activeSbom;
        SBOM inactiveSbom;
        SBOM unassignedSbom;
        SBOMComponent rootComponent;
        SBOMComponent compA;
        SBOMComponent compB;
        SBOMComponent inactiveComponent;
        SBOMComponent compUnassigned;
        Asset asset;
        AssetComponent acPresent;
        AssetComponent acAbsent;
        VulnerabilityAlert alertOnComponent;
        VulnerabilityAlert alertOnAssetComponent;
        CompromiseFinding finding;
    }

}
