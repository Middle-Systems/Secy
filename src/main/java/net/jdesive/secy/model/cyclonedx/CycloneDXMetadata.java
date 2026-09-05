package net.jdesive.secy.model.cyclonedx;

import lombok.Data;

import java.util.Date;
import java.util.List;

@Data
public class CycloneDXMetadata {

    private Date timestamp;

    private CycloneDXToolComponent tools;

    private CycloneDXComponent component;

}
