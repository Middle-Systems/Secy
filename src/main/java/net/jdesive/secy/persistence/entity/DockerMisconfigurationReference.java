package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@Entity
@Table(name = "docker_misconfiguration_reference")
public class DockerMisconfigurationReference {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String url;

    @JsonIncludeProperties(value = {"id"})
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private DockerComplianceReportMisconfig report;

}
