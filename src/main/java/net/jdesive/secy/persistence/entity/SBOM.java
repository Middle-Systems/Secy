package net.jdesive.secy.persistence.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
@Transactional
@Table(name = "sbom")
public class SBOM {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String format;

    private String specVersion;

    private int version;

    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<SBOMTool> tools = new ArrayList<>();

    @OneToOne(cascade = CascadeType.ALL)
    private SBOMComponent component;

    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<SBOMComponent> components = new ArrayList<>();

}
