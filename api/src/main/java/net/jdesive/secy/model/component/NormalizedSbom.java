package net.jdesive.secy.model.component;

import lombok.Builder;
import lombok.Singular;

import java.util.List;

/**
 * A whole SBOM document, normalised — the only thing {@code SBOMService} accepts.
 *
 * @param format        the detected format, which decides {@code sbom.format}
 * @param specVersion   {@code specVersion} for CycloneDX ({@code "1.5"}), {@code spdxVersion} for SPDX
 *                      ({@code "SPDX-2.3"}) — stored verbatim so the document can be identified later
 * @param version       CycloneDX's document revision; SPDX has no counterpart and reports 1
 * @param rootComponent the thing the document describes (CycloneDX {@code metadata.component}, SPDX's
 *                      {@code DESCRIBES} target), or null. Held on {@code sbom.component} and
 *                      <b>not</b> correlated — it is the product itself, not a dependency
 * @param components    the dependencies, root excluded
 * @param tools         whatever generated the document
 */
@Builder
public record NormalizedSbom(SbomFormat format,
                             String specVersion,
                             int version,
                             NormalizedComponent rootComponent,
                             @Singular List<NormalizedComponent> components,
                             @Singular List<NormalizedTool> tools) {

    /** An SBOM generator. CycloneDX {@code metadata.tools}, SPDX {@code creationInfo.creators}. */
    public record NormalizedTool(String name, String version, String group, String type) {
    }

    public NormalizedSbom {
        components = components == null ? List.of() : List.copyOf(components);
        tools = tools == null ? List.of() : List.copyOf(tools);
    }

}
