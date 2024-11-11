package net.jdesive.secy.model.kev;

import lombok.Data;

import java.util.Date;
import java.util.List;

@Data
public class KevResponse {

    private String title;
    private String catalogVersion;
    private Date dateReleased;
    private int count;

    private List<KevResponseVulnerability> vulnerabilities;
}
