package net.jdesive.secy.model.nvd;

import lombok.Getter;

import java.util.Date;
import java.util.List;

@Getter
public class NVDCVE {

    private String id;

    private String sourceIdentifier;

    private Date published;

    private Date lastModified;

    private String vulnStatus;

    private List<NVDCVETag> cveTags;

    private List<NVDCVEDescription> descriptions;

    private NVDCVEMetrics metrics;

    private List<NVDCVEConfiguration> configurations;

    private List<NVDCVEReference> references;

    private List<NVDCVEWeakness> weaknesses;

}
