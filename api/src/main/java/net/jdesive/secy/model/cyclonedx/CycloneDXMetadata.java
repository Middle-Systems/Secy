package net.jdesive.secy.model.cyclonedx;

import lombok.Data;

import java.util.Date;
import java.util.List;

@Data
public class CycloneDXMetadata {

    private Date timestamp;

    private CycloneDXToolComponent tools;

    private CycloneDXComponent component;

    /** CycloneDX 1.5+ (M1e). See {@code CycloneDXNormalizer} for the phase → stage mapping. */
    private List<CycloneDXLifecycle> lifecycles;

}
