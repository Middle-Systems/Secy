package net.jdesive.secy.model.nvd;

import lombok.Getter;

import java.util.List;

@Getter
public class NVDCVEReference {

    private String url;

    private String source;

    private List<String> tags;

}
