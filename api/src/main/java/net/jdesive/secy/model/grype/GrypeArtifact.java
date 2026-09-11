package net.jdesive.secy.model.grype;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * The package half of a Grype match.
 *
 * @param name      package name
 * @param version   installed version
 * @param type      Syft's package type — {@code npm}, {@code java-archive}, {@code apk},
 *                  {@code deb}, {@code rpm}, {@code go-module}, …
 * @param purl      the PURL Syft built. <b>Preferred over everything else</b>: it is a real PURL from
 *                  the tool that read the package metadata, not a guess reconstructed from a name.
 * @param locations where in the scanned artifact it lives
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GrypeArtifact(String name, String version, String type, String purl,
                            List<GrypeLocation> locations) {

    /** One place the package was found. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GrypeLocation(String path, String layerID) {
    }

    public GrypeArtifact {
        locations = locations == null ? List.of() : List.copyOf(locations);
    }

    /** The first recorded location, or null — Grype lists them in discovery order. */
    public GrypeLocation primaryLocation() {
        return locations.isEmpty() ? null : locations.get(0);
    }

}
