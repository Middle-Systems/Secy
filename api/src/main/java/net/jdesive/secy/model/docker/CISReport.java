package net.jdesive.secy.model.docker;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

/**
 * A {@code trivy --compliance <spec>} document: the CIS-benchmark shape, which is
 * <b>not</b> the {@code trivy image} shape {@code net.jdesive.secy.model.trivy.TrivyReport} models.
 * Top level is {@code ID}/{@code Title}/{@code Results[]}, and each {@code Results[]} element is a
 * benchmark <em>control</em> whose own nested {@code Results[]} holds the findings.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class CISReport {

    @JsonProperty("ID")
    private String id;

    /**
     * What was audited, when the invocation recorded it.
     *
     * <p>The compliance format does not guarantee this the way {@code trivy image} does — most
     * {@code --compliance} runs emit no artifact identity at all, which is why the upload endpoint
     * accepts a {@code name} parameter and requires one when neither this nor a nested
     * {@code Target} names anything. Read when present because a report that knows its own subject
     * should not have to be told it.
     */
    @JsonProperty("ArtifactName")
    private String artifactName;

    @JsonProperty("Version")
    private String version;

    @JsonProperty("Title")
    private String title;

    @JsonProperty("Description")
    private String description;

    @JsonProperty("RelatedResources")
    private List<String> relatedResources;

    @JsonProperty("Results")
    private List<CISReportResult> results;

}
