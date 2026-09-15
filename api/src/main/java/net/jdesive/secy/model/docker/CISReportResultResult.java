package net.jdesive.secy.model.docker;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class CISReportResultResult {

    @JsonProperty("Target")
    private String target;

    @JsonProperty("Class")
    private String classType;

    @JsonProperty("Type")
    private String type;

    @JsonProperty("Misconfigurations")
    private List<CISReportMisconfig> misconfigurations;

    @JsonProperty("Vulnerabilities")
    private List<CISReportVulnerability> vulnerabilities;

}
