package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * One check inside a {@link DockerComplianceControl}: a configuration rule that was evaluated, and
 * what to do about it if it failed.
 *
 * <h2>Not a vulnerability, and deliberately not in the funnel</h2>
 *
 * <p>Phase 5 routes the compliance report's <em>vulnerability</em> half into the ordinary
 * {@code VulnerabilityAlert} funnel, because "this package has this CVE" is the same statement
 * however it was observed. A misconfiguration is not that statement. It has no CVE, so no EPSS, no
 * KEV membership and no exploit maturity — every input the actionable funnel ranks on is absent.
 * Forcing it through would either fabricate those values or add a permanently-null second class of
 * row to the product's primary screen. It stays its own concept, read through
 * {@code GET /compliance/reports/{id}}.
 */
@Getter
@Setter
@Entity
@Table(name = "docker_compliance_report_misconfig")
public class DockerComplianceReportMisconfig {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Trivy's misconfiguration {@code Type}, e.g. {@code Docker Security Check}. */
    private String type;

    /** Trivy's own check id, e.g. {@code DS002}. Previously dropped on the floor; restored Phase 5. */
    @Column(length = 64)
    private String checkId;

    private String avdId;

    private String title;

    @Column(length = 10024)
    private String description;

    @Column(length = 4096)
    private String message;

    /** The remediation text. Surfaced verbatim by the Compliance view — the point of the screen. */
    @Column(length = 4096)
    private String resolution;

    private String severity;

    /** PASS / FAIL / SKIP. A finding Trivy reported with no status at all is a FAIL. */
    @Enumerated(EnumType.STRING)
    @Column(length = 16, nullable = false)
    private ComplianceStatus status = ComplianceStatus.FAIL;

    /** Which scanned target this check ran against — Trivy {@code results[].Target}. */
    @Column(length = 512)
    private String target;

    private String primaryUrl;

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    @JsonIgnore
    private List<DockerMisconfigurationReference> references = new ArrayList<>();

    /** The control this check belongs to. */
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    @JsonIgnore
    private DockerComplianceControl control;

    /**
     * Denormalized parent, alongside {@link #control}, so the paged misconfiguration list for a
     * report is one indexed predicate instead of a join through the control table.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    @JsonIgnore
    private DockerComplianceReport report;

}
