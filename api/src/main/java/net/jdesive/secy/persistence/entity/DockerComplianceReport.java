package net.jdesive.secy.persistence.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
@Table(name = "docker_compliance_report")
public class DockerComplianceReport {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String reportId;

    private String title;

    private String description;

    private String version;

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<DockerComplianceReportReference> references = new ArrayList<>();

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<DockerComplianceReportMisconfig> misconfigurations = new ArrayList<>();

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<DockerComplianceReportVulnerability> vulnerabilities = new ArrayList<>();

}
