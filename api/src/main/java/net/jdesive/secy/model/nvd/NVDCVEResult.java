package net.jdesive.secy.model.nvd;

import lombok.Getter;

import java.util.Date;
import java.util.List;

@Getter
public class NVDCVEResult {

    private int resultsPerPage;

    private int startIndex;

    private int totalResults;

    private String format;

    private String version;

    private Date timestamp;

    private List<NVDVulnerability> vulnerabilities;

}
