package net.jdesive.secy.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

/**
 * One affected version interval of an {@link OsvAdvisory}.
 *
 * <h2>The simplification, stated plainly</h2>
 *
 * <p>An OSV {@code affected[].ranges[]} entry is <em>an ordered list of events</em>, not an
 * interval: {@code [{introduced: "1.0"}, {fixed: "1.2"}, {introduced: "2.0"}, {fixed: "2.1"}]} is one
 * range object describing two disjoint intervals. This table stores <b>one interval per row</b> —
 * each {@code introduced} event paired with the {@code fixed} or {@code last_affected} event that
 * closes it, or left open when none does. The feed ingester walks the event list and emits a row per
 * pair.
 *
 * <p>That loses nothing correlation uses. "Is this version affected?" is a union over the intervals,
 * and a union over rows is the same union. What it does lose is the ability to round-trip the
 * original record byte-for-byte, which nothing needs.
 *
 * <p>{@link #rangeType} is kept for provenance ({@code SEMVER} / {@code ECOSYSTEM} / {@code GIT}).
 * It does <b>not</b> select the comparison: {@code VersionSchemes.forEcosystem} does, from the
 * advisory's ecosystem. A {@code GIT} range carries commit hashes rather than versions and cannot be
 * evaluated at all — the matcher skips those rows rather than comparing hashes as if they were
 * version strings.
 */
@Getter
@Setter
@Entity
@Table(name = "osv_affected_range")
public class OsvAffectedRange {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "advisory_id", nullable = false)
    @ToString.Exclude
    private OsvAdvisory advisory;

    /** OSV {@code ranges[].type}: {@code SEMVER}, {@code ECOSYSTEM} or {@code GIT}. */
    @Column(length = 32)
    private String rangeType;

    /** Inclusive lower bound. OSV's {@code "0"} sentinel means "from the first release". */
    @Column(length = 255)
    private String introduced;

    /** The first version that is <b>not</b> affected — an exclusive upper bound, and the fix version. */
    @Column(length = 255)
    private String fixed;

    /** The last version that <b>is</b> affected — an inclusive upper bound, with no fix implied. */
    @Column(name = "last_affected", length = 255)
    private String lastAffected;

    /**
     * True when this row can be evaluated against a version string. {@code GIT} ranges carry commit
     * hashes and are skipped by the matcher.
     */
    public boolean isEvaluable() {
        return !"GIT".equalsIgnoreCase(rangeType);
    }

}
