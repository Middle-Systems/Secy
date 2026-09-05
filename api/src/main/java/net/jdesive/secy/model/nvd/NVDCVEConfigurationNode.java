package net.jdesive.secy.model.nvd;

import lombok.Getter;

import java.util.List;

@Getter
public class NVDCVEConfigurationNode {

    private String operator;

    private boolean negate;

    private List<NVDCVEConfigurationNodeCPEMatch> cpeMatch;

}
