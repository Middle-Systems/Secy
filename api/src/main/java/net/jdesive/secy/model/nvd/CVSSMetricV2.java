package net.jdesive.secy.model.nvd;

import lombok.Getter;

@Getter
public class CVSSMetricV2 {

    private String source;
    private String type;

    private CVSSData cvssData;

    private String baseSeverity;

    private double exploitabilityScore;

    private double impactScore;

    private boolean acInsufInfo;

    private boolean obtainAllPrivilege;

    private boolean obtainUserPrivilege;

    private boolean obtainOtherPrivilege;

    private boolean userInteractionRequired;

}
