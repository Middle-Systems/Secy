package net.jdesive.secy.model.nvd;

import lombok.Getter;

import java.util.List;

@Getter
public class NVDCVEWeakness {

    private String source;

    private String type;

    private List<NVDCVEWeaknessDescription> description;

}
