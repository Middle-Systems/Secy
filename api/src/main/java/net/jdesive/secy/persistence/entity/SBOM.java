package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
@Entity
@Transactional
@Table(name = "sbom")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class SBOM {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String format;

    private String specVersion;

    private int version;

    private String productVersion;

    private boolean active;

    private String status;

    private LocalDateTime lastScannedAt;

    private LocalDateTime uploadDate = LocalDateTime.now();

    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<SBOMTool> tools = new ArrayList<>();

    @OneToOne(cascade = CascadeType.ALL)
    private SBOMComponent component;

    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<SBOMComponent> components = new ArrayList<>();

    @JsonIncludeProperties(value = {"id"})
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private Product product;

    // This creates a virtual field in your JSON
    @JsonProperty("totalVulnerabilities")
    public int getTotalVulnerabilities() {
        if (components == null) return 0;
        return components.stream()
                .mapToInt(c -> c.getVulnerabilityAlerts() != null ? c.getVulnerabilityAlerts().size() : 0)
                .sum();
    }

}
