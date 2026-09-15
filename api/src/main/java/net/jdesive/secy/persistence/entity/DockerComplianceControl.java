package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * One benchmark control inside a {@link DockerComplianceReport} — {@code 4.1 "Ensure that a user for
 * the container has been created"} — with its rolled-up verdict.
 *
 * <h2>Why this row exists at all</h2>
 *
 * <p>The pre-Phase-5 model flattened Trivy's compliance document straight into a bag of
 * misconfigurations and threw the control layer away, which made "how many controls pass" —
 * the one number a compliance screen is for — unanswerable. Trivy nests
 * {@code Results[] (control) → results[] (target) → misconfigurations[] (check)}; this is the middle
 * layer, restored.
 *
 * @see ComplianceStatus#rollUp for how a control's checks become one verdict
 */
@Getter
@Setter
@Entity
@Table(name = "docker_compliance_control")
public class DockerComplianceControl {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** The benchmark's own control number, e.g. {@code 4.1}. Unique within a report. */
    @Column(length = 64)
    private String controlId;

    private String name;

    @Column(length = 4096)
    private String description;

    @Column(length = 32)
    private String severity;

    @Enumerated(EnumType.STRING)
    @Column(length = 16, nullable = false)
    private ComplianceStatus status = ComplianceStatus.SKIP;

    /** How many checks under this control failed. Zero on a PASS or SKIP. */
    @Column(name = "failed_checks", nullable = false)
    private int failedChecks;

    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    @JsonIgnore
    private DockerComplianceReport report;

    @OneToMany(mappedBy = "control", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    @JsonIgnore
    private List<DockerComplianceReportMisconfig> misconfigurations = new ArrayList<>();

}
