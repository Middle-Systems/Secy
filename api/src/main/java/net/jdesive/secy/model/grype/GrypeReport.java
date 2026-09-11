package net.jdesive.secy.model.grype;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * The top level of {@code grype -o json} output.
 *
 * <p>Nothing like Trivy's shape: Grype is match-centric (a flat {@code matches[]} list, each entry
 * pairing a vulnerability with the artifact that carries it) where Trivy is target-centric (results
 * grouped by scanned target). Grype also emits a real PURL on the artifact whenever Syft could build
 * one, which is why this path needs no ecosystem guessing for anything but bare OS packages.
 *
 * @param matches the findings
 * @param source  what was scanned. {@code target} is a string for a directory scan and an object
 *                ({@code {userInput, imageID, tags:[…]}}) for an image, so it is kept as a raw node
 *                and read defensively — see {@code GrypeNormalizer}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GrypeReport(List<GrypeMatch> matches, GrypeSource source) {

    /** What Grype scanned. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GrypeSource(String type, JsonNode target) {
    }

    public GrypeReport {
        matches = matches == null ? List.of() : List.copyOf(matches);
    }

}
