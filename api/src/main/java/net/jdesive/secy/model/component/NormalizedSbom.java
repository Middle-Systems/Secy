package net.jdesive.secy.model.component;

import lombok.Builder;
import lombok.Singular;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

/**
 * A whole SBOM document, normalised — the only thing {@code SBOMService} accepts.
 *
 * @param format               the detected format, which decides {@code sbom.format}
 * @param specVersion          {@code specVersion} for CycloneDX ({@code "1.5"}), {@code spdxVersion} for SPDX
 *                             ({@code "SPDX-2.3"}) — stored verbatim so the document can be identified later
 * @param version              CycloneDX's document revision; SPDX has no counterpart and reports 1
 * @param rootComponent        the thing the document describes (CycloneDX {@code metadata.component}, SPDX's
 *                             {@code DESCRIBES} target), or null. Held on {@code sbom.component} and
 *                             <b>not</b> correlated — it is the product itself, not a dependency
 * @param components           the dependencies, root excluded
 * @param tools                whatever generated the document
 * @param declaredLifecycleStage the SDLC stage the document itself declares (M1e) — CycloneDX 1.5+
 *                             {@code metadata.lifecycles[]}, mapped by {@code CycloneDXNormalizer}; null
 *                             when absent, ambiguous/conflicting, or the format has no equivalent (SPDX).
 *                             The {@code ?stage=} API param, when given, wins over this at upload time —
 *                             see {@code SBOMService#createPlaceholder}.
 * @param cryptoAssetsIgnoredForSpecVersion (M1g) count of {@code cryptographic-asset} components
 *                             this document declared whose {@code cryptoProperties} were skipped
 *                             because {@code specVersion} is below the 1.6 floor — the component
 *                             itself still normalizes as a plain row. Always 0 for SPDX.
 * @param documentTimestamp    (M1h) the document's own declared creation time — CycloneDX
 *                             {@code metadata.timestamp}, SPDX {@code creationInfo.created} —
 *                             converted to system-default-zone {@link LocalDateTime}. Null when
 *                             absent or unparseable; never {@code sbom.uploadDate} (Secy's own ingest
 *                             time)
 * @param authors              (M1h) who created the SBOM DATA, never the tool that generated the
 *                             document — CycloneDX {@code metadata.authors[].name}/{@code .email},
 *                             plus 1.6 {@code metadata.manufacturer.name}; SPDX
 *                             {@code creationInfo.creators[]} entries prefixed {@code Person:}/
 *                             {@code Organization:} with the prefix stripped. Deduplicated, document
 *                             order
 * @param dependencyRelationshipRefs (M1h) the bom-refs/SPDXIDs that take part in at least one
 *                             declared dependency relationship. <b>Presence only, not a graph</b> —
 *                             M1l will replace this with a real edge list; see
 *                             {@code SbomQualityScorer}
 */
@Builder
public record NormalizedSbom(SbomFormat format,
                             String specVersion,
                             int version,
                             NormalizedComponent rootComponent,
                             @Singular List<NormalizedComponent> components,
                             @Singular List<NormalizedTool> tools,
                             SbomLifecycleStage declaredLifecycleStage,
                             int cryptoAssetsIgnoredForSpecVersion,
                             LocalDateTime documentTimestamp,
                             @Singular List<String> authors,
                             @Singular Set<String> dependencyRelationshipRefs) {

    /** An SBOM generator. CycloneDX {@code metadata.tools}, SPDX {@code creationInfo.creators}. */
    public record NormalizedTool(String name, String version, String group, String type) {
    }

    public NormalizedSbom {
        components = components == null ? List.of() : List.copyOf(components);
        tools = tools == null ? List.of() : List.copyOf(tools);
        authors = authors == null ? List.of() : List.copyOf(authors);
        dependencyRelationshipRefs = dependencyRelationshipRefs == null ? Set.of() : Set.copyOf(dependencyRelationshipRefs);
    }

    /**
     * True when this document declared at least one component and every one of them is a
     * {@code cryptographic-asset} (M1g) — a standalone CBOM. See ROADMAP.md's D1 for the interaction
     * this has with the M1e active-SBOM slot.
     */
    public boolean isCryptoOnly() {
        return !components.isEmpty()
                && components.stream().allMatch(c -> net.jdesive.secy.model.cbom.CryptoAssets.isCryptoAsset(c.type()));
    }

}
