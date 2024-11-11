package net.jdesive.secy.persistence.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Entity
@Table(name = "docker_misconfiguration_alert")
public class DockerMisconfigurationAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private Date createdDate;

    private Date lastModifiedDate;

    private boolean dismissed;

    private String dismissedReason;

    private String dismissedEvidenceUrl;

    @OneToOne(cascade = CascadeType.ALL)
    private DockerComplianceReportMisconfig misconfiguration;

}
