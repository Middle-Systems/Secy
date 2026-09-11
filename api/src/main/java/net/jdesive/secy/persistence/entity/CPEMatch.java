package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.transaction.annotation.Transactional;

@Getter
@Setter
@ToString
@Entity
@Transactional
@Table(name = "cpe_match")
public class CPEMatch {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private boolean vulnerable;

    private String criteria;

    private String matchCriteriaId;

    /* ------------------------------------------------------------------ */
    /* Version range                                                      */
    /* ------------------------------------------------------------------ */

    /**
     * NVD's {@code versionStartIncluding} — inclusive lower bound of the affected range.
     *
     * <p>These four columns are the difference between "log4j-core is affected" and "log4j-core
     * between 2.0-beta9 and 2.14.1 is affected". The {@code version} field inside {@link #criteria}
     * is a bare {@code *} on almost every modern CPE row precisely because the range lives here;
     * reading the version out of the criteria string — which is what correlation used to do — reads
     * that wildcard and matches everything.
     *
     * <p><b>Existing rows will be null until NVD is re-ingested.</b> {@code POST /nvd/ingest}
     * repopulates them; a row with all four null and a wildcard version is treated as
     * {@code MatchConfidence.HEURISTIC} rather than dropped, so a stale database degrades to the old
     * behaviour rather than going silent.
     */
    @Column(name = "version_start_including", length = 255)
    private String versionStartIncluding;

    /** NVD's {@code versionStartExcluding} — exclusive lower bound. See {@link #versionStartIncluding}. */
    @Column(name = "version_start_excluding", length = 255)
    private String versionStartExcluding;

    /** NVD's {@code versionEndIncluding} — inclusive upper bound. See {@link #versionStartIncluding}. */
    @Column(name = "version_end_including", length = 255)
    private String versionEndIncluding;

    /**
     * NVD's {@code versionEndExcluding} — exclusive upper bound, and therefore the first fixed
     * version. This is where the CPE path's approximate fix version comes from
     * ({@code FixSource.CPE_RANGE}).
     */
    @Column(name = "version_end_excluding", length = 255)
    private String versionEndExcluding;

    /** True when any of the four range attributes is set — i.e. this row bounds its versions. */
    public boolean hasVersionRange() {
        return notBlank(versionStartIncluding) || notBlank(versionStartExcluding)
                || notBlank(versionEndIncluding) || notBlank(versionEndExcluding);
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    @JsonIncludeProperties(value = {"id"})
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private CPEOperator operator;

}
