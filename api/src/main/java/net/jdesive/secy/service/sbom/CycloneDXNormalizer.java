package net.jdesive.secy.service.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import net.jdesive.secy.model.cbom.CryptoAssets;
import net.jdesive.secy.model.cbom.NormalizedCryptoAsset;
import net.jdesive.secy.model.component.DependencyEdgeCollector;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.component.SbomFormat;
import net.jdesive.secy.service.cbom.CryptoPropertiesExtractor;
import net.jdesive.secy.model.cyclonedx.CycloneDXComponent;
import net.jdesive.secy.model.cyclonedx.CycloneDXComponentLicense;
import net.jdesive.secy.model.cyclonedx.CycloneDXExternalReference;
import net.jdesive.secy.model.cyclonedx.CycloneDXFile;
import net.jdesive.secy.model.cyclonedx.CycloneDXHash;
import net.jdesive.secy.model.cyclonedx.CycloneDXMetadata;
import net.jdesive.secy.model.cyclonedx.CycloneDXSwid;
import net.jdesive.secy.model.cyclonedx.CycloneDXTool;
import net.jdesive.secy.model.component.SecondaryIdentifiers;
import net.jdesive.secy.model.cyclonedx.CycloneDXLifecycle;
import net.jdesive.secy.persistence.entity.ComponentHash;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.ZoneId;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
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
 *
 * <h2>M1g: CycloneDX 1.6+ {@code cryptoProperties}</h2>
 *
 * <p>CycloneDX 1.2+ JSON is accepted as always; {@code cryptoProperties} on a
 * {@code cryptographic-asset} component is read only when {@code 1.6 <= specVersion < 2.0} (see
 * {@link CycloneDxSpecVersion#supportsCryptoAssets}) — below the floor, the component still
 * normalises as a plain row, just without a {@link NormalizedComponent#crypto()}; this is a skip, not
 * a rejection. The check applies to {@code components[]} only, never {@code metadata.component} (the
 * root), which is never correlated or crypto-classified either way. Pre-standard IBM CBOM drafts
 * (top-level {@code "bomFormat": "CBOM"}) are already rejected by {@code SbomParser}'s
 * {@code bomFormat} check, before this class ever runs — deliberately unsupported, not a bug.
 */
@Slf4j
@Component
public class CycloneDXNormalizer {

    public NormalizedSbom normalize(CycloneDXFile file) {
        NormalizedSbom.NormalizedSbomBuilder builder = NormalizedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .specVersion(file.getSpecVersion())
                .version(file.getVersion());

        CycloneDXMetadata metadata = file.getMetadata();
        String rootBomRef = null;
        if (metadata != null) {
            if (metadata.getComponent() != null) {
                // Root is never crypto-classified, even when it is itself a cryptographic-asset and
                // the document supports CBOM — see this class's Javadoc.
                NormalizedComponent root = component(metadata.getComponent(), false);
                builder.rootComponent(root);
                rootBomRef = root.bomRef();
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
            builder.declaredLifecycleStage(declaredLifecycleStage(metadata.getLifecycles()));

            // M1h: the document's own declared creation time — never sbom.uploadDate (Secy's ingest time).
            builder.documentTimestamp(metadata.getTimestamp() == null ? null
                    : java.time.LocalDateTime.ofInstant(metadata.getTimestamp().toInstant(), ZoneId.systemDefault()));
            builder.authors(authors(metadata));
        }

        boolean cbom = CycloneDxSpecVersion.supportsCryptoAssets(file.getSpecVersion());
        int ignoredForSpecVersion = 0;
        if (file.getComponents() != null) {
            for (CycloneDXComponent cdx : file.getComponents()) {
                if (cdx == null) {
                    continue;
                }
                if (!cbom && CryptoAssets.isCryptoAsset(cdx.getType())) {
                    ignoredForSpecVersion++;
                }
                builder.component(component(cdx, cbom));
            }
        }
        builder.cryptoAssetsIgnoredForSpecVersion(ignoredForSpecVersion);
        builder.dependencyRelationshipRefs(dependencyRefs(file.getDependencies()));

        // M1l: the directed edge list and the document's own root ref(s) — see dependencyEdges' and
        // dependencyRootRefs' Javadoc on NormalizedSbom.
        DependencyEdgeCollector collector = new DependencyEdgeCollector();
        collectDependencyEdges(file.getDependencies(), collector);
        if (collector.overflowed()) {
            log.warn("CycloneDX document declared too many dependency edges — discarding the whole "
                    + "dependency graph; every component will classify as UNKNOWN depth");
        }
        builder.dependencyEdges(collector.edges());
        builder.dependencyRootRefs(rootBomRef == null ? java.util.Set.of() : java.util.Set.of(rootBomRef));

        return builder.build();
    }

    private NormalizedComponent component(CycloneDXComponent cdx, boolean extractCrypto) {
        boolean isCrypto = CryptoAssets.isCryptoAsset(cdx.getType());
        NormalizedCryptoAsset crypto = extractCrypto && isCrypto
                ? CryptoPropertiesExtractor.extract(cdx.getCryptoProperties())
                : null;
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
                .identifiers(identifiers(cdx))
                .crypto(crypto)
                .supplier(organizationName(cdx.getSupplier()))
                .build();
    }

    /**
     * An OrganizationalEntity {@code {name, url[], contact[]}} → its {@code name}, when present and
     * textual/non-blank. Never throws — a string, an array, or an object with no {@code name} all
     * return null rather than reject the document. Used for {@code component.supplier} (M1h) and
     * {@code metadata.manufacturer} (M1h author source).
     */
    private static String organizationName(JsonNode n) {
        if (n == null || !n.isObject()) {
            return null;
        }
        JsonNode name = n.get("name");
        if (name == null || !name.isTextual()) {
            return null;
        }
        String trimmed = name.asText().trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * {@code metadata.authors[]} (OrganizationalContact entries) plus 1.6 {@code metadata.manufacturer}
     * (M1h) — who created the SBOM DATA, never the tool. Each {@code authors[]} object entry
     * contributes its {@code name}, falling back to {@code email}; a bare textual entry (non-standard,
     * but tolerated) contributes its own text; anything else is skipped. Deduplicated with a
     * {@code LinkedHashSet}, each entry truncated to 255 — matches {@code SBOMService}'s
     * {@code MAX_SHORT_TEXT}, applied again defensively here since this is a parse-time helper with no
     * access to that constant.
     */
    private static List<String> authors(CycloneDXMetadata metadata) {
        Set<String> out = new LinkedHashSet<>();
        JsonNode authors = metadata.getAuthors();
        if (authors != null && authors.isArray()) {
            for (JsonNode entry : authors) {
                String value = null;
                if (entry.isObject()) {
                    JsonNode name = entry.get("name");
                    if (name != null && name.isTextual() && !name.asText().isBlank()) {
                        value = name.asText().trim();
                    } else {
                        JsonNode email = entry.get("email");
                        if (email != null && email.isTextual() && !email.asText().isBlank()) {
                            value = email.asText().trim();
                        }
                    }
                } else if (entry.isTextual() && !entry.asText().isBlank()) {
                    value = entry.asText().trim();
                }
                if (value != null) {
                    out.add(value.length() > 255 ? value.substring(0, 255) : value);
                }
            }
        }
        String manufacturer = organizationName(metadata.getManufacturer());
        if (manufacturer != null) {
            out.add(manufacturer.length() > 255 ? manufacturer.substring(0, 255) : manufacturer);
        }
        return new ArrayList<>(out);
    }

    /**
     * Top-level {@code dependencies[]} (M1h) → the set of bom-refs that take part in at least one
     * declared dependency relationship, for presence-only scoring — see
     * {@code net.jdesive.secy.service.quality.SbomQualityScorer}. For each {@code {ref, dependsOn[]}}
     * object entry: {@code ref} is always added (even with an empty/absent {@code dependsOn[]} —
     * CycloneDX defines {@code {ref:X, dependsOn:[]}} as an explicit "X has no dependencies"
     * assertion, which NTIA accepts), and every textual element of {@code dependsOn[]} is added too.
     * Malformed shapes (not an array, entries not objects) degrade to an empty set rather than throw.
     * CycloneDX 1.6 {@code provides[]} is deliberately ignored.
     */
    private static Set<String> dependencyRefs(JsonNode dependencies) {
        Set<String> out = new LinkedHashSet<>();
        if (dependencies == null || !dependencies.isArray()) {
            return out;
        }
        for (JsonNode entry : dependencies) {
            if (entry == null || !entry.isObject()) {
                continue;
            }
            JsonNode ref = entry.get("ref");
            if (ref != null && ref.isTextual() && !ref.asText().isBlank()) {
                out.add(ref.asText().trim());
            }
            JsonNode dependsOn = entry.get("dependsOn");
            if (dependsOn != null && dependsOn.isArray()) {
                for (JsonNode dep : dependsOn) {
                    if (dep != null && dep.isTextual() && !dep.asText().isBlank()) {
                        out.add(dep.asText().trim());
                    }
                }
            }
        }
        return out;
    }

    /**
     * Top-level {@code dependencies[]} (M1l) → the directed edge list: for each {@code {ref,
     * dependsOn[]}} object entry, one {@code ref -> d} edge per textual non-blank element of {@code
     * dependsOn[]}. An empty {@code dependsOn[]} adds no edge (unlike {@link #dependencyRefs}'s
     * presence set, which still records {@code ref} itself). Malformed shapes (not an array, entries
     * not objects, a non-array {@code dependsOn}) degrade to no edges, never throw. CycloneDX 1.6
     * {@code provides[]} is deliberately ignored, same as {@link #dependencyRefs}.
     */
    private static void collectDependencyEdges(JsonNode dependencies, DependencyEdgeCollector collector) {
        if (dependencies == null || !dependencies.isArray()) {
            return;
        }
        for (JsonNode entry : dependencies) {
            if (entry == null || !entry.isObject()) {
                continue;
            }
            JsonNode ref = entry.get("ref");
            String from = ref != null && ref.isTextual() ? ref.asText() : null;
            if (from == null || from.isBlank()) {
                continue;
            }
            JsonNode dependsOn = entry.get("dependsOn");
            if (dependsOn == null || !dependsOn.isArray()) {
                continue;
            }
            for (JsonNode dep : dependsOn) {
                if (dep != null && dep.isTextual() && !dep.asText().isBlank()) {
                    collector.add(from, dep.asText());
                }
            }
        }
    }

    /**
     * CycloneDX {@code component.cpe} / {@code component.swid} (M1c) → the normalised identifier
     * list. Applies to {@code metadata.component} (the root) too, since it goes through this same
     * {@link #component} method. Neither ever feeds {@code identityKey} — see
     * {@link SecondaryIdentifiers}.
     */
    private List<NormalizedComponent.Identifier> identifiers(CycloneDXComponent cdx) {
        List<NormalizedComponent.Identifier> out = new ArrayList<>();
        NormalizedComponent.Identifier cpe = SecondaryIdentifiers.cpe(cdx.getCpe(), SecondaryIdentifiers.CDX_CPE);
        if (cpe != null) {
            out.add(cpe);
        }
        CycloneDXSwid swid = cdx.getSwid();
        if (swid != null) {
            NormalizedComponent.Identifier swidIdentifier = SecondaryIdentifiers.swid(
                    swid.getTagId(), swid.getName(), swid.getVersion(), SecondaryIdentifiers.CDX_SWID);
            if (swidIdentifier != null) {
                out.add(swidIdentifier);
            }
        }
        return SecondaryIdentifiers.dedupe(out);
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

    /**
     * CycloneDX 1.5+ {@code metadata.lifecycles[].phase} → {@link SbomLifecycleStage} (M1e).
     *
     * <table border="1">
     *   <caption>CycloneDX phase to lifecycle stage</caption>
     *   <tr><th>CycloneDX phase</th><th>Stage</th></tr>
     *   <tr><td>{@code pre-build}</td><td>{@code SOURCE}</td></tr>
     *   <tr><td>{@code build}</td><td>{@code BUILD}</td></tr>
     *   <tr><td>{@code post-build}</td><td>{@code ANALYZED}</td></tr>
     *   <tr><td>{@code operations}</td><td>{@code DEPLOYED}</td></tr>
     *   <tr><td>{@code design}, {@code discovery}, {@code decommission}, a custom name-only entry, or
     *       anything unrecognised</td><td>ignored (contributes nothing)</td></tr>
     * </table>
     *
     * <p>Distinct mapped stages are collected: exactly one → that stage; zero (nothing mapped) or
     * more than one (conflicting phases) → {@code null} — M1c's "flag, don't merge" spirit applies
     * here too: guessing which of two declared phases is right would be worse than leaving the field
     * unknown.
     */
    private static SbomLifecycleStage declaredLifecycleStage(List<CycloneDXLifecycle> lifecycles) {
        if (lifecycles == null || lifecycles.isEmpty()) {
            return null;
        }
        Set<SbomLifecycleStage> mapped = EnumSet.noneOf(SbomLifecycleStage.class);
        for (CycloneDXLifecycle lifecycle : lifecycles) {
            if (lifecycle == null || lifecycle.getPhase() == null) {
                continue;
            }
            SbomLifecycleStage stage = switch (lifecycle.getPhase().trim().toLowerCase(Locale.ROOT)) {
                case "pre-build" -> SbomLifecycleStage.SOURCE;
                case "build" -> SbomLifecycleStage.BUILD;
                case "post-build" -> SbomLifecycleStage.ANALYZED;
                case "operations" -> SbomLifecycleStage.DEPLOYED;
                default -> null;
            };
            if (stage != null) {
                mapped.add(stage);
            }
        }
        return mapped.size() == 1 ? mapped.iterator().next() : null;
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
