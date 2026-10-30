package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

/**
 * One resolved, directed {@code component depends on dependsOnComponent} edge (M1l, ROADMAP.md —
 * "Dependency graph preserved") — only edges whose both ends resolved to a persisted {@link
 * SBOMComponent} row of the same {@link SBOM} (the root row included) are stored here; edges
 * through an unresolved ref (no matching {@code bomRef}, or a ref ambiguous/duplicated across
 * components) are not, though their effect is still reflected in each component's {@code
 * dependency_depth}/{@code dependency_distance}/{@code dependency_path} since the BFS runs over the
 * document's full ref graph, not just the rows that end up here. This table feeds the M1d lineage
 * graph's {@code DEPENDS_ON} edges ({@code LineageSourceReader}); M1i's scoring reads the derived
 * columns on {@link SBOMComponent} directly and never queries this table.
 *
 * <p>No JPA associations at all — {@link #sbomId}/{@link #componentId}/{@link #dependsOnComponentId}
 * are plain, unrelated {@code UUID} columns, matching the 029b ({@code TenantMembershipRole})
 * precedent: a real {@code @ManyToOne} here would make Hibernate generate an H2 foreign key in
 * tests, which could block an unrelated test's SBOM/component cleanup. PostgreSQL still gets real
 * cascading foreign keys, written directly in migration {@code 030b-sbom-component-dependency}.
 */
@Getter
@Setter
@Entity
@Table(name = "sbom_component_dependency",
        uniqueConstraints = @UniqueConstraint(name = "uq_sbom_component_dependency_edge",
                columnNames = {"component_id", "depends_on_component_id"}))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class SBOMComponentDependency {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "sbom_id", nullable = false)
    private UUID sbomId;

    @Column(name = "component_id", nullable = false)
    private UUID componentId;

    @Column(name = "depends_on_component_id", nullable = false)
    private UUID dependsOnComponentId;

}
