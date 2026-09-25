package net.jdesive.secy.lineage;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.lineage.source.AssetComponentRow;
import net.jdesive.secy.lineage.source.AssetRow;
import net.jdesive.secy.lineage.source.ComponentRow;
import net.jdesive.secy.lineage.source.CompromiseFindingRow;
import net.jdesive.secy.lineage.source.LineageSourceData;
import net.jdesive.secy.lineage.source.ProductRow;
import net.jdesive.secy.lineage.source.SbomRow;
import net.jdesive.secy.lineage.source.VulnerabilityAlertRow;
import net.jdesive.secy.lineage.source.VulnerabilityRow;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/**
 * Reads exactly the Postgres rows the M1d lineage graph needs for one tenant, via plain JPQL
 * constructor expressions — no new methods added to any existing {@code JpaRepository} (keeps the
 * Spring Data REST surface those repositories back untouched).
 *
 * <p>Runs fine against H2 (see {@code LineageSourceReaderTest}) — nothing here is Postgres- or
 * AGE-specific, only the write side ({@link AgeLineageGraphWriter}) is.
 *
 * <h2>Scope rules baked into these queries (ROADMAP.md, M1d)</h2>
 * <ul>
 *   <li>Only {@code active} SBOMs (the Unassigned bucket's SBOMs are all active per M1a, so they
 *       are included).</li>
 *   <li>A component query excludes the owning SBOM's root/metadata component — the one row
 *       {@code SBOM.component} points at directly rather than appearing in {@code SBOM.components}
 *       (see {@code SBOMService#ingestDocument}).</li>
 *   <li>Only asset components with {@code presentInLastScan = true}.</li>
 *   <li>Every nullable single-valued association is read through an explicit {@code left join} —
 *       never an implicit {@code x.y.id} dot-path, which JPQL turns into an inner join in the
 *       {@code select} clause and would silently drop rows whose association is null.</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class LineageSourceReader {

    private final EntityManager entityManager;

    @Transactional(readOnly = true)
    public LineageSourceData read(UUID tenantId) {
        List<ProductRow> products = entityManager.createQuery("""
                        select new net.jdesive.secy.lineage.source.ProductRow(
                            p.id, p.name, p.tagValue, p.unassigned, p.createdAt)
                        from Product p
                        where p.tenantId = :tenantId
                        """, ProductRow.class)
                .setParameter("tenantId", tenantId)
                .getResultList();

        List<SbomRow> sboms = entityManager.createQuery("""
                        select new net.jdesive.secy.lineage.source.SbomRow(
                            s.id, pr.id, s.format, s.specVersion, s.version, s.productVersion, s.status,
                            s.uploadDate, s.ingestionSource, s.sourceConnectorId, s.lifecycleStage)
                        from SBOM s
                        left join s.product pr
                        where s.tenantId = :tenantId and s.active = true
                        """, SbomRow.class)
                .setParameter("tenantId", tenantId)
                .getResultList();

        List<ComponentRow> components = entityManager.createQuery("""
                        select new net.jdesive.secy.lineage.source.ComponentRow(
                            c.id, s.id, c.name, c.version, c.purl, c.identityKey, c.type, c.identityConfidence)
                        from SBOMComponent c
                        join c.sbom s
                        left join s.component root
                        where s.tenantId = :tenantId and s.active = true and (root.id is null or c.id <> root.id)
                        """, ComponentRow.class)
                .setParameter("tenantId", tenantId)
                .getResultList();

        List<AssetRow> assets = entityManager.createQuery("""
                        select new net.jdesive.secy.lineage.source.AssetRow(
                            a.id, pr.id, a.type, a.name, a.status, a.scanner, a.lastScannedAt)
                        from Asset a
                        left join a.product pr
                        where a.tenantId = :tenantId
                        """, AssetRow.class)
                .setParameter("tenantId", tenantId)
                .getResultList();

        List<AssetComponentRow> assetComponents = entityManager.createQuery("""
                        select new net.jdesive.secy.lineage.source.AssetComponentRow(
                            ac.id, a.id, ac.name, ac.version, ac.purl, ac.identityKey, ac.ecosystem, ac.source)
                        from AssetComponent ac
                        join ac.asset a
                        where a.tenantId = :tenantId and ac.presentInLastScan = true
                        """, AssetComponentRow.class)
                .setParameter("tenantId", tenantId)
                .getResultList();

        List<VulnerabilityAlertRow> alerts = entityManager.createQuery("""
                        select new net.jdesive.secy.lineage.source.VulnerabilityAlertRow(
                            al.id, c.id, ac.id, v.id, al.lifecycleState, al.triageState, al.actionable,
                            al.actionableReason, al.matchConfidence, al.fixState, al.exploitMaturity,
                            al.cvssScore, al.epssScore, al.kevDueDate)
                        from VulnerabilityAlert al
                        left join al.component c
                        left join al.assetComponent ac
                        left join al.vulnerability v
                        where al.tenantId = :tenantId
                        """, VulnerabilityAlertRow.class)
                .setParameter("tenantId", tenantId)
                .getResultList();

        List<VulnerabilityRow> vulnerabilities = entityManager.createQuery("""
                        select distinct new net.jdesive.secy.lineage.source.VulnerabilityRow(
                            v.id, v.baseSeverity, v.cvssScore, v.cveStatus)
                        from VulnerabilityAlert al
                        join al.vulnerability v
                        where al.tenantId = :tenantId
                        """, VulnerabilityRow.class)
                .setParameter("tenantId", tenantId)
                .getResultList();

        List<CompromiseFindingRow> compromiseFindings = entityManager.createQuery("""
                        select new net.jdesive.secy.lineage.source.CompromiseFindingRow(
                            f.id, c.id, ac.id, f.type, f.confidence, f.severity, f.source, f.iocId,
                            f.lifecycleState, f.triageState)
                        from CompromiseFinding f
                        left join f.component c
                        left join f.assetComponent ac
                        where f.tenantId = :tenantId
                        """, CompromiseFindingRow.class)
                .setParameter("tenantId", tenantId)
                .getResultList();

        return new LineageSourceData(
                sortedById(products, ProductRow::id),
                sortedById(sboms, SbomRow::id),
                sortedById(components, ComponentRow::id),
                sortedById(assets, AssetRow::id),
                sortedById(assetComponents, AssetComponentRow::id),
                sortedByStringId(vulnerabilities, VulnerabilityRow::id),
                sortedById(alerts, VulnerabilityAlertRow::id),
                sortedById(compromiseFindings, CompromiseFindingRow::id));
    }

    private static <T> List<T> sortedById(List<T> rows, java.util.function.Function<T, UUID> idOf) {
        return rows.stream().sorted(Comparator.comparing(idOf)).toList();
    }

    private static <T> List<T> sortedByStringId(List<T> rows, java.util.function.Function<T, String> idOf) {
        return rows.stream().sorted(Comparator.comparing(idOf)).toList();
    }

}
