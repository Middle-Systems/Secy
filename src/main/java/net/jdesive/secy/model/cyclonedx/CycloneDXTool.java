package net.jdesive.secy.model.cyclonedx;

import lombok.Data;

import java.util.List;

@Data
public class CycloneDXTool {

    private String vendor;
    private String name;
    private String version;

    private List<CycloneDXToolHashes> hashes;

}
