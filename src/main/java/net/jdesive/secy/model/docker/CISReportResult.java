package net.jdesive.secy.model.docker;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class CISReportResult {

    @JsonProperty("ID")
    private String id;

    @JsonProperty("Name")
    private String name;

    @JsonProperty("Description")
    private String description;

    @JsonProperty("Severity")
    private String severity;

    @JsonProperty("Results")
    private List<CISReportResultResult> results;

}
