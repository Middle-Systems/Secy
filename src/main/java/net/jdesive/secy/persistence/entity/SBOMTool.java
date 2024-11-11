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
@Entity
@Transactional
@Table(name = "sbom_tool")
public class SBOMTool {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String vendor;

    private String name;

    private String version;

    @JsonIncludeProperties(value = {"id"})
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private SBOM sbom;

}
