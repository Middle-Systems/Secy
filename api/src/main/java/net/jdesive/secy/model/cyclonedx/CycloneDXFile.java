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
     * Top-level {@code dependencies[]} (M1h) — {@code {ref, dependsOn[]}} entries. Bound as a raw
     * tree, same reasoning as {@link CycloneDXComponent#getCryptoProperties()}: M1h only checks
     * presence of a bom-ref in this structure (see {@code CycloneDXNormalizer#dependencyRefs}), never
     * builds or validates the graph (M1l's job), so a typed POJO would buy nothing but a new way to
     * reject an otherwise-valid document.
     */
    private JsonNode dependencies;

}
