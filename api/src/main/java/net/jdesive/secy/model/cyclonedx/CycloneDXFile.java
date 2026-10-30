package net.jdesive.secy.model.cyclonedx;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

import java.util.List;

@Data
public class CycloneDXFile {

    private String bomFormat;
    private String specVersion;
    private String serialNumber;
    private int version;

    private CycloneDXMetadata metadata;

    private List<CycloneDXComponent> components;

    /**
     * Top-level {@code dependencies[]} ({@code {ref, dependsOn[]}} entries) — bound as a raw tree,
     * same reasoning as {@link CycloneDXComponent#getCryptoProperties()}: a typed POJO would buy
     * nothing but a new way to reject an otherwise-valid document. Read twice downstream: M1h's
     * {@code CycloneDXNormalizer#dependencyRefs} for presence-only NTIA scoring, and M1l's {@code
     * CycloneDXNormalizer#collectDependencyEdges} for the real directed edge graph (ROADMAP.md,
     * M1l — "Dependency graph preserved").
     */
    private JsonNode dependencies;

}
