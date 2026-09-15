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
 * One affected version interval of a {@link MaliciousPackage} — the malicious-packages twin of
 * {@link OsvAffectedRange}, with the same one-interval-per-row flattening of OSV's event lists and
 * the same {@code GIT}-is-not-evaluable rule.
 *
 * <p>A separate table rather than a shared one because {@code OsvAffectedRange} has a
 * {@code not null} FK to {@code osv_advisory}; sharing would have meant making that FK nullable and
 * adding a discriminator, to save one four-column table.
 */
@Getter
@Setter
@Entity
@Table(name = "malicious_package_range")
public class MaliciousPackageRange {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "package_id", nullable = false)
    @ToString.Exclude
    private MaliciousPackage maliciousPackage;

    /** {@code ranges[].type}: {@code SEMVER}, {@code ECOSYSTEM} or {@code GIT}. */
    @Column(name = "range_type", length = 32)
    private String rangeType;

    /** Inclusive lower bound. OSV's {@code "0"} sentinel means "from the first release". */
    @Column(length = 255)
    private String introduced;

    /** The first version that is <b>not</b> affected. Rare here: malware does not get "fixed". */
    @Column(length = 255)
    private String fixed;

    /** The last version that <b>is</b> affected. */
    @Column(name = "last_affected", length = 255)
    private String lastAffected;

    /** See {@link OsvAffectedRange#isEvaluable()} — {@code GIT} ranges carry commit hashes. */
    public boolean isEvaluable() {
        return !"GIT".equalsIgnoreCase(rangeType);
    }

    /**
     * True when this interval covers <b>every</b> version of the package: it starts at OSV's
     * {@code "0"} sentinel (or states no lower bound at all) and nothing closes it above.
     *
     * <p>This is the normal shape for a malicious publish, and the one
     * {@link MaliciousPackage#affectsAllVersions()} is built on. The lower-bound test is not
     * decoration: {@code {introduced: "2.1.0"}} with no fix is also unbounded <em>above</em>, but it
     * says nothing about 1.0.0 — treating that as "all versions" would raise a CONFIRMED compromise
     * finding against a version the feed never accused. Such a range goes through ordinary interval
     * arithmetic instead, like any other bounded-below range.
     */
    public boolean isWholePackage() {
        return isBlank(fixed) && isBlank(lastAffected)
                && (isBlank(introduced) || "0".equals(introduced.trim()));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

}
