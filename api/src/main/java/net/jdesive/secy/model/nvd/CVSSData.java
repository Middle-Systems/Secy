package net.jdesive.secy.model.nvd;

import lombok.Getter;

@Getter
public class CVSSData {

    private String version;

    private String vectorString;

    private String accessVector;

    private String accessComplexity;

    private String authentication;

    private String confidentialityImpact;

    private String integrityImpact;

    private String availabilityImpact;

    private double baseScore;

}
