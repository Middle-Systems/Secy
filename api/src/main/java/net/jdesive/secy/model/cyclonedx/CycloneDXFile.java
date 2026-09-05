package net.jdesive.secy.model.cyclonedx;

import lombok.Data;

import java.util.List;

@Data
public class CycloneDXFile {

    private String bomFormat;
    private String specVersion;
    private String serialNumber;
    private int version;

    private CycloneDXMetadata metadata;

    private List<CycloneDXComponent> components;

}
