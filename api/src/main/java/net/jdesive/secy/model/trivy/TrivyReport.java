package net.jdesive.secy.model.trivy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * The top level of {@code trivy image -f json} output.
 *
 * <h2>This is not the CIS/compliance shape</h2>
 *
 * <p>{@code net.jdesive.secy.model.docker.CISReport} models a completely different Trivy invocation —
 * {@code trivy config} / a compliance benchmark — whose JSON is
 * {@code {ID, Version, Title, Results:[{results:[{...}]}]}}. The two share a vendor and nothing else.
 * Vulnerability scanning is Phase 4 (this package); compliance is Phase 5 (that one). Do not merge
 * them.
 *
 * @param schemaVersion Trivy's own report schema revision (2 at the time of writing)
 * @param artifactName  what was scanned — {@code alpine:3.18}, a directory path, …
 * @param artifactType  {@code container_image} / {@code filesystem} / {@code repository}
 * @param results       one entry per target within the artifact: the OS package database, then one
 *                      per language-package manifest found
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TrivyReport(
        @JsonProperty("SchemaVersion") Integer schemaVersion,
        @JsonProperty("ArtifactName") String artifactName,
        @JsonProperty("ArtifactType") String artifactType,
        @JsonProperty("Results") List<TrivyResult> results) {

    public TrivyReport {
        results = results == null ? List.of() : List.copyOf(results);
    }

}
