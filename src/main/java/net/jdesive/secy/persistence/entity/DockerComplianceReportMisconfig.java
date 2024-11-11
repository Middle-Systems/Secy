package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
@Table(name = "docker_compliance_report_misconfig")
public class DockerComplianceReportMisconfig {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String type;

    private String avdId;

    private String title;

    @Column(length = 10024)
    private String description;

    private String message;

    private String resolution;

    private String severity;

    private String primaryUrl;

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<DockerMisconfigurationReference> references = new ArrayList<>();

    @JsonIncludeProperties(value = {"id"})
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private DockerComplianceReport report;

}
