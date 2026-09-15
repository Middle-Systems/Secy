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
 * One OpenSSF Malicious Packages record ({@code MAL-…}), <b>as it applies to one package</b>.
 *
 * <h2>Why this is not just another {@code OsvAdvisory} row</h2>
 *
 * <p>The source is OSV-format and the ingester is structurally the Phase 2 one, so folding these
 * into {@code osv_advisory} was the obvious first idea. It is wrong for three reasons:
 *
 * <ol>
 *   <li><b>{@code OsvMatcher} would silently drop every one of them.</b> It requires a {@code CVE-}
 *       alias, because the funnel it feeds is CVE-keyed end to end (KEV, EPSS, the CVE browser, the
 *       detail view). A {@code MAL-} record has no CVE and never will — malware is not a
 *       vulnerability. Rows that no matcher can read are dead weight.</li>
 *   <li><b>The tables are read by different questions.</b> {@code osv_advisory} answers "which
 *       advisories affect this package at this version". This one answers "is this package known-bad
 *       at all", and the common answer is that <em>every</em> version is, which
 *       {@link #affectsAllVersions()} makes a first-class property rather than a range-arithmetic
 *       result.</li>
 *   <li><b>The provenance differs.</b> {@link #origins} and {@link #iocFirstSeen}/{@link #iocLastSeen}
 *       come from {@code database_specific.malicious-packages-origins[]}, which only this feed has,
 *       and IOC aging reads them on a schedule no advisory row participates in.</li>
 * </ol>
 *
 * <p>Same one-row-per-{@code (record, ecosystem, package)} shape as {@code OsvAdvisory}, and for the
 * same reason: correlation always starts from "I have this package", so the row it wants must be
 * findable by {@code (ecosystem, name)} alone.
 *
 * <p><b>Known feed gap — there is no category.</b> The roadmap anticipated a
 * typo-squat/dependency-confusion classification. The published records do not carry one: every
 * record's {@code affected[].database_specific.cwes[]} is {@code CWE-506 "Embedded Malicious Code"}
 * and nothing distinguishes the attack shape structurally. {@link #category} is therefore populated
 * only when a record actually supplies {@code database_specific.category}, and is null in practice
 * today. The reporting {@link #origins} are the useful discriminator the data does have.
 */
@Getter
@Setter
@Entity
@Table(name = "malicious_package",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_malicious_package_record_package",
                columnNames = {"mal_id", "ecosystem", "package_name"}),
        indexes = {
                @Index(name = "idx_malicious_package_lookup", columnList = "ecosystem, package_name"),
                @Index(name = "idx_malicious_package_mal_id", columnList = "mal_id")
        })
public class MaliciousPackage {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** The record id — {@code MAL-2026-4502}. Also the IOC id a {@link CompromiseFinding} cites. */
    @Column(name = "mal_id", nullable = false, length = 255)
    private String malId;

    /**
     * OSV ecosystem name, normalised to the spelling {@code ComponentCoordinate} produces
     * ({@code npm}, {@code PyPI}, {@code Maven}, {@code Go}, …).
     *
     * <p>Normalisation matters more here than in {@code osv_advisory}: the upstream repository's
     * directory names are lower-case ({@code osv/malicious/pypi/…}) while the records inside spell
     * the ecosystem canonically ({@code "PyPI"}). The ingester takes the record's spelling and the
     * matcher compares case-insensitively, so neither side has to know which was which.
     */
    @Column(nullable = false, length = 64)
    private String ecosystem;

    /** Ecosystem-native package name, verbatim from {@code affected[].package.name}. */
    @Column(name = "package_name", nullable = false, length = 512)
    private String packageName;

    /** {@code affected[].package.purl} when the record supplies one. Provenance only. */
    @Column(length = 512)
    private String purl;

    /**
     * The specific bad publishes, from {@code affected[].versions[]}. A hit here is the strongest
     * statement the feed makes about a version and maps to {@link CompromiseConfidence#CONFIRMED}.
     */
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "malicious_package_version",
            joinColumns = @JoinColumn(name = "package_id"))
    @Column(name = "version", length = 255, nullable = false)
    @ToString.Exclude
    private Set<String> versions = new LinkedHashSet<>();

    /**
     * Affected intervals, flattened one-per-row exactly as {@code OsvAffectedRange} does. Usually a
     * single unbounded {@code introduced: "0"} — see {@link #affectsAllVersions()}.
     */
    @OneToMany(mappedBy = "maliciousPackage", cascade = CascadeType.ALL, orphanRemoval = true,
            fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<MaliciousPackageRange> ranges = new ArrayList<>();

    /** {@code summary} — "Malicious code in bucket-protocol-sdk-v2 (npm)". */
    @Column(length = 1024)
    private String summary;

    /** {@code details} — the per-source write-up, which is the actual analyst evidence. */
    @Column(length = 10024)
    private String details;

    /** See the class note: absent from the published data, kept for a feed that starts supplying one. */
    @Column(length = 64)
    private String category;

    /**
     * Comma-joined distinct {@code database_specific.malicious-packages-origins[].source} values —
     * {@code ghsa-malware}, {@code amazon-inspector}, {@code checkmarx},
     * {@code ossf-package-analysis}. This is the "origin" the roadmap asked for and the closest the
     * data comes to a classification.
     */
    @Column(length = 512)
    private String origins;

    /** The record's {@code references[]} array, stored as raw JSON. Rendered, never queried. */
    @Column(name = "references_json", length = 4096)
    private String referencesJson;

    private LocalDateTime published;

    /** Record {@code modified} timestamp. */
    private LocalDateTime modified;

    /**
     * Set when the record was withdrawn (the upstream {@code osv/withdrawn/} tree, or a
     * {@code withdrawn} field). A withdrawn record must not raise findings; the matcher skips it
     * rather than the ingester deleting the row, so a reversal needs no re-import.
     */
    private LocalDateTime withdrawn;

    /** Earliest {@code origins[].modified_time}, falling back to {@link #published}. */
    @Column(name = "ioc_first_seen")
    private LocalDateTime iocFirstSeen;

    /** Latest {@code origins[].modified_time}, falling back to {@link #modified}. Drives IOC aging. */
    @Column(name = "ioc_last_seen")
    private LocalDateTime iocLastSeen;

    /** When the ingester last wrote this row. */
    @Column(name = "last_ingested_at")
    private LocalDateTime lastIngestedAt;

    /** True when this record should be evaluated at all. */
    public boolean isCurrent() {
        return withdrawn == null;
    }

    /**
     * Whether the feed asserts the <em>whole package</em> is malicious.
     *
     * <p>True when the record enumerates no specific versions and carries at least one range
     * covering everything ({@code introduced: "0"}, nothing closing it above) — or no ranges at all,
     * meaning the record names the package and nothing narrower. That is the normal shape for a
     * malicious publish: the package is not a good library that went bad at 2.3.1, it was published
     * as malware, so there is no safe side of the range and no fix to upgrade to.
     *
     * <p>Treated as {@link CompromiseConfidence#CONFIRMED} rather than a range inference, because
     * no arithmetic is involved: "all versions" covers whatever version the operator has, including
     * a component that declares no version at all.
     *
     * <p>Note the {@code versions} guard. When a record <em>does</em> enumerate the bad publishes,
     * that list is the narrower and more accurate statement, and the accompanying
     * {@code introduced: "0"} range is the feed's way of saying "we cannot express the enumeration
     * as an interval" — not a claim that every version is bad. Honouring the enumeration is what
     * stops a clean 1.0.0 of a package whose 1.0.1 was hijacked from being reported as malware.
     */
    public boolean affectsAllVersions() {
        if (versions != null && !versions.isEmpty()) {
            return false;
        }
        if (ranges == null || ranges.isEmpty()) {
            return true;
        }
        return ranges.stream().anyMatch(MaliciousPackageRange::isWholePackage);
    }

}
