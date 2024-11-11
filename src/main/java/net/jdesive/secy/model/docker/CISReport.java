package net.jdesive.secy.model.docker;

import com.fasterxml.jackson.annotation.JacksonAnnotation;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class CISReport {

    @JsonProperty("ID")
    private String id;

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
