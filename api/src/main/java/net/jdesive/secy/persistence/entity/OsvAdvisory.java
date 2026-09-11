package net.jdesive.secy.persistence.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * One OSV advisory, <b>as it applies to one package</b>.
 *
 * <h2>Why the primary key is not the OSV id</h2>
 *
 * <p>An OSV record's {@code affected[]} array can name several packages, sometimes across several
 * ecosystems — one GHSA covering both the npm and the Maven publication of a library, say. This
 * table stores <b>one row per (record, ecosystem, package)</b>, keyed by a surrogate UUID with a
 * unique constraint on that triple. Correlation always starts from "I have this package at this
 * version"; storing the record whole would mean loading and then discarding the affected entries for
 * packages nobody in the estate ships.
 *
 * <p>The consequence is that record-level data — {@link #aliases}, {@link #summary},
 * {@link #severity} — is duplicated across the rows of a multi-package record. That is a handful of
 * duplicated strings on a table whose whole point is to be read by exactly one query, and it buys a
 * matcher that needs no second hop to resolve a CVE id.
 *
 * <h2>What "affected" means here</h2>
 *
 * <p>OSV expresses affected versions two ways, and a record may use either or both:
 * {@link #ranges} (intervals) and {@link #versions} (an enumerated list). They are a union, and the
 * matcher evaluates both. An enumerated hit is stronger evidence than a range hit — the advisory
 * literally names the version — which is what separates {@code MatchConfidence.EXACT} from
 * {@code RANGE}.
 *
 * <p><b>Owned by Phase 2, populated by the OSV feed ingester.</b> Nothing in this phase writes rows;
 * see {@code PHASE2-CONTRACT.md} for the ingest contract and {@link OsvEcosystemCursor} for the
 * high-water mark the ingester keeps.
 */
@Getter
@Setter
@Entity
@Table(name = "osv_advisory",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_osv_advisory_record_package",
                columnNames = {"osv_id", "ecosystem", "package_name"}),
        indexes = {
                @Index(name = "idx_osv_advisory_lookup", columnList = "ecosystem, package_name"),
                @Index(name = "idx_osv_advisory_osv_id", columnList = "osv_id")
        })
public class OsvAdvisory {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** The OSV record id: {@code GHSA-…}, {@code PYSEC-…}, {@code GO-…}, {@code RUSTSEC-…}, {@code CVE-…}. */
    @Column(name = "osv_id", nullable = false, length = 255)
    private String osvId;

    /**
     * OSV ecosystem name, verbatim from {@code affected[].package.ecosystem} — {@code npm},
     * {@code Maven}, {@code PyPI}, {@code Go}, {@code NuGet}, {@code RubyGems}, {@code crates.io},
     * {@code Packagist}, {@code Hex}, {@code Pub}, and the release-qualified distro forms
     * ({@code Alpine:v3.16}). Matched case-insensitively; {@code VersionSchemes.forEcosystem}
     * ignores anything after the colon.
     */
    @Column(nullable = false, length = 64)
    private String ecosystem;

    /**
     * Ecosystem-native package name, verbatim from {@code affected[].package.name}. Maven uses
     * {@code groupId:artifactId}, Go the full module path, npm the {@code @scope/name} form.
     * {@code ComponentCoordinate} produces the same spelling from a PURL.
     */
    @Column(name = "package_name", nullable = false, length = 512)
    private String packageName;

    /** {@code affected[].package.purl} when the record supplies one. Provenance only. */
    @Column(length = 512)
    private String purl;

    /**
     * Record-level {@code aliases[]} plus the record's own id, so a lookup by CVE id finds it.
     * A {@code CVE-} entry here is what resolves this advisory onto a {@code Vulnerability} row.
     */
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "osv_advisory_alias",
            joinColumns = @JoinColumn(name = "advisory_id"),
            indexes = @Index(name = "idx_osv_advisory_alias_alias", columnList = "alias"))
    @Column(name = "alias", length = 255, nullable = false)
    @ToString.Exclude
    private Set<String> aliases = new LinkedHashSet<>();

    /**
     * Affected version intervals. See {@link OsvAffectedRange} for the one-interval-per-row
     * flattening of OSV's event lists.
     */
    @OneToMany(mappedBy = "advisory", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<OsvAffectedRange> ranges = new ArrayList<>();

    /**
     * The enumerated {@code affected[].versions[]} list some records carry instead of, or alongside,
     * ranges. Compared with the ecosystem's scheme, not by string equality, so {@code 1.0} in the
     * advisory still matches {@code 1.0.0} in the SBOM.
     */
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "osv_affected_version",
            joinColumns = @JoinColumn(name = "advisory_id"))
    @Column(name = "version", length = 255, nullable = false)
    @ToString.Exclude
    private Set<String> versions = new LinkedHashSet<>();

    /** Highest severity band the record states, when it states one — {@code CRITICAL} … {@code LOW}. */
    @Column(length = 32)
    private String severity;

    /** CVSS vector string from {@code severity[]}, e.g. {@code CVSS:3.1/AV:N/AC:L/…}. */
    @Column(name = "cvss_vector", length = 255)
    private String cvssVector;

    @Column(length = 1024)
    private String summary;

    @Column(length = 10024)
    private String details;

    /** The record's {@code references[]} array, stored as raw JSON. Rendered, never queried. */
    @Column(name = "references_json", length = 4096)
    private String referencesJson;

    /** Record {@code modified} timestamp — what {@link OsvEcosystemCursor} advances against. */
    private LocalDateTime modified;

    private LocalDateTime published;

    /**
     * Set when the record was withdrawn. A withdrawn advisory must not raise alerts; the matcher
     * skips these rows rather than the ingester deleting them, so a withdrawal that is later
     * reversed needs no re-import.
     */
    private LocalDateTime withdrawn;

    /** When the ingester last wrote this row. */
    @Column(name = "last_ingested_at")
    private LocalDateTime lastIngestedAt;

    /** True when this advisory should be evaluated at all. */
    public boolean isCurrent() {
        return withdrawn == null;
    }

    /** The first {@code CVE-} alias, which is how an advisory resolves onto a {@code Vulnerability}. */
    public String cveAlias() {
        if (aliases == null) {
            return null;
        }
        return aliases.stream()
                .filter(alias -> alias != null && alias.regionMatches(true, 0, "CVE-", 0, 4))
                .findFirst()
                .orElse(null);
    }

}
