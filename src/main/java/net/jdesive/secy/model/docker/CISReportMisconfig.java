package net.jdesive.secy.model.docker;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class CISReportMisconfig {

    @JsonProperty("Type")
    private String type;

    @JsonProperty("ID")
    private String id;

    @JsonProperty("AVDID")
    private String avdId;

    @JsonProperty("Title")
    private String title;

    @JsonProperty("Description")
    private String description;

    @JsonProperty("Message")
    private String message;

    @JsonProperty("Resolution")
    private String resolution;

    @JsonProperty("Severity")
    private String severity;

    @JsonProperty("PrimaryURL")
    private String primaryUrl;

    @JsonProperty("References")
    private List<String> references;

    @JsonProperty("Status")
    private String status;

}
