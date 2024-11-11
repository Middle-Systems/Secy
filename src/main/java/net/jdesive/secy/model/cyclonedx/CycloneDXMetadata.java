package net.jdesive.secy.model.cyclonedx;

import lombok.Data;

import java.util.Date;
import java.util.List;

@Data
public class CycloneDXMetadata {

    private Date timestamp;

    private List<CycloneDXTool> tools;

    private CycloneDXComponent component;

}
