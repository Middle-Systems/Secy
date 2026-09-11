package net.jdesive.secy.model.spdx;

import lombok.Data;

import java.util.List;

/**
 * SPDX {@code creationInfo}. Only {@code creators} is read, to fill {@code sbom_tool}.
 *
 * <p>Creators are free-text strings prefixed by their kind: {@code "Tool: syft-0.98.0"},
 * {@code "Organization: Acme"}, {@code "Person: jane"}. Only the {@code Tool:} ones map to anything
 * Secy stores.
 */
@Data
public class SpdxCreationInfo {

    private String created;

    private List<String> creators;

    private String licenseListVersion;

}
