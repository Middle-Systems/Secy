package net.jdesive.secy.service.sbom;

import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.component.SbomFormat;
import net.jdesive.secy.model.cyclonedx.CycloneDXComponent;
import net.jdesive.secy.model.cyclonedx.CycloneDXComponentLicense;
import net.jdesive.secy.model.cyclonedx.CycloneDXExternalReference;
import net.jdesive.secy.model.cyclonedx.CycloneDXFile;
import net.jdesive.secy.model.cyclonedx.CycloneDXHash;
import net.jdesive.secy.model.cyclonedx.CycloneDXMetadata;
import net.jdesive.secy.model.cyclonedx.CycloneDXTool;
import net.jdesive.secy.persistence.entity.ComponentHash;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * CycloneDX (1.2–1.6 JSON) → {@link NormalizedSbom}.
 *
 * <p>This is {@code SBOMService.parseCdxComponent} lifted out of the persistence path. Nothing
 * downstream of here touches a {@code CycloneDX*} type again.
 *
 * <p>Every field is optional as far as this class is concerned. A document with no {@code metadata},
 * no {@code components}, a component with no name — all of them normalise rather than throw, because
 * an SBOM that is 99% parseable is worth correlating and a hard failure on one malformed entry
 * loses the other 99%.
 */
@Component
public class CycloneDXNormalizer {

    public NormalizedSbom normalize(CycloneDXFile file) {
        NormalizedSbom.NormalizedSbomBuilder builder = NormalizedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .specVersion(file.getSpecVersion())
                .version(file.getVersion());

        CycloneDXMetadata metadata = file.getMetadata();
        if (metadata != null) {
            if (metadata.getComponent() != null) {
                builder.rootComponent(component(metadata.getComponent()));
            }
            if (metadata.getTools() != null && metadata.getTools().getComponents() != null) {
                for (CycloneDXTool tool : metadata.getTools().getComponents()) {
                    if (tool == null) {
                        continue;
                    }
                    builder.tool(new NormalizedSbom.NormalizedTool(
                            tool.getName(), tool.getVersion(), tool.getGroup(), tool.getType()));
                }
            }
        }

        if (file.getComponents() != null) {
            for (CycloneDXComponent cdx : file.getComponents()) {
                if (cdx == null) {
                    continue;
                }
                builder.component(component(cdx));
            }
        }

        return builder.build();
    }

    private NormalizedComponent component(CycloneDXComponent cdx) {
        return NormalizedComponent.builder()
                .name(cdx.getName())
                .version(cdx.getVersion())
                .purl(cdx.getPurl())
                .type(cdx.getType())
                .description(cdx.getDescription())
                .bomRef(cdx.getBomRef())
                .licenses(licenses(cdx))
                .externalReferences(references(cdx))
                .hashes(hashes(cdx))
                .build();
    }

    /**
     * CycloneDX {@code hashes[]} → the normalised digest list.
     *
     * <p>{@code ComponentHash.of} does the normalising and returns null for anything malformed — a
     * non-hex "digest", an over-long algorithm name — which is dropped here rather than stored.
     * Same rule as {@link #licenses}: an unusable entry is not worth a parse failure, and an
     * unusable digest could never match anything anyway.
     */
    private List<NormalizedComponent.ComponentHashValue> hashes(CycloneDXComponent cdx) {
        if (cdx.getHashes() == null) {
            return List.of();
        }
        List<NormalizedComponent.ComponentHashValue> out = new ArrayList<>();
        for (CycloneDXHash hash : cdx.getHashes()) {
            if (hash == null) {
                continue;
            }
            ComponentHash normalized = ComponentHash.of(hash.getAlg(), hash.getContent());
            if (normalized != null) {
                out.add(new NormalizedComponent.ComponentHashValue(
                        normalized.getAlgorithm(), normalized.getValue()));
            }
        }
        return out;
    }

    /**
     * CycloneDX allows either {@code licenses[].license.id} (an SPDX identifier) or
     * {@code licenses[].expression}. Only the former is bound today; an entry with neither is
     * dropped rather than stored as an empty string.
     */
    private List<String> licenses(CycloneDXComponent cdx) {
        if (cdx.getLicenses() == null) {
            return List.of();
        }
        Set<String> out = new LinkedHashSet<>();
        for (CycloneDXComponentLicense licence : cdx.getLicenses()) {
            if (licence == null || licence.getLicense() == null) {
                continue;
            }
            String id = licence.getLicense().getId();
            if (id != null && !id.isBlank()) {
                out.add(id.trim());
            }
        }
        return new ArrayList<>(out);
    }

    private List<NormalizedComponent.ExternalReference> references(CycloneDXComponent cdx) {
        if (cdx.getExternalReferences() == null) {
            return List.of();
        }
        List<NormalizedComponent.ExternalReference> out = new ArrayList<>();
        for (CycloneDXExternalReference reference : cdx.getExternalReferences()) {
            if (reference == null || reference.getUrl() == null || reference.getUrl().isBlank()) {
                continue;
            }
            out.add(new NormalizedComponent.ExternalReference(reference.getType(), reference.getUrl().trim()));
        }
        return out;
    }

}
