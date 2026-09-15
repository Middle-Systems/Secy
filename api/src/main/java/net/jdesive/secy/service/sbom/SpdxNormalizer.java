package net.jdesive.secy.service.sbom;

import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.component.SbomFormat;
import net.jdesive.secy.model.spdx.SpdxChecksum;
import net.jdesive.secy.model.spdx.SpdxDocument;
import net.jdesive.secy.model.spdx.SpdxExternalRef;
import net.jdesive.secy.model.spdx.SpdxPackage;
import net.jdesive.secy.model.spdx.SpdxRelationship;
import net.jdesive.secy.persistence.entity.ComponentHash;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * SPDX JSON (2.2 and 2.3) → {@link NormalizedSbom}.
 *
 * <h2>Scope — what this parser does NOT do, and why that is the right MVP line</h2>
 *
 * <ul>
 *   <li><b>The relationship graph is not traversed.</b> Only {@code DESCRIBES} is read, to identify
 *       the root package. {@code DEPENDS_ON} / {@code CONTAINS} / {@code DEV_DEPENDENCY_OF} would
 *       give a dependency <em>tree</em> (direct vs. transitive, and a path to blame), but correlation
 *       is a flat set operation — every package you ship is a package you can be attacked through,
 *       whatever the edge that put it there. The tree is presentation, and there is no view for it
 *       yet. {@code packages[]} minus the root is therefore the complete correlation input.</li>
 *   <li><b>{@code files[]} and {@code snippets[]} are ignored.</b> File-level SPDX describes source
 *       provenance and licensing, not shipped dependencies; nothing in the funnel is keyed on a file.
 *       (Phase 6 will want file <em>hashes</em> for malware matching — that is a
 *       {@code checksums[]} read on top of this parser, not a reason to bind files now.)</li>
 *   <li><b>{@code hasFiles}, annotations, {@code otherLicensingInfo} (LicenseRef- definitions),
 *       verification codes and SPDX-2.3 {@code builtDate}/{@code validUntilDate} are ignored</b> —
 *       none feed correlation, enrichment or the UI.</li>
 *   <li><b>SPDX RDF/XML/tag-value is out of scope entirely</b>, per the roadmap ("SPDX JSON only").</li>
 * </ul>
 *
 * <p>A package with neither a PURL nor a name is dropped; everything else is emitted, because a
 * package with only a name still correlates through the CPE fallback.
 */
@Component
public class SpdxNormalizer {

    /** SPDX sentinels that mean "no information", not a value. */
    private static final Set<String> NO_VALUE = Set.of("NOASSERTION", "NONE");

    private static final String DESCRIBES = "DESCRIBES";

    /**
     * SPDX 2.3 {@code primaryPackagePurpose} → the CycloneDX {@code type} vocabulary the rest of Secy
     * already speaks. Best-effort by definition: the two vocabularies are not isomorphic, and SPDX
     * 2.2 has no purpose field at all.
     */
    private static final Map<String, String> PURPOSES = Map.ofEntries(
            Map.entry("LIBRARY", "library"),
            Map.entry("APPLICATION", "application"),
            Map.entry("FRAMEWORK", "framework"),
            Map.entry("CONTAINER", "container"),
            Map.entry("OPERATING_SYSTEM", "operating-system"),
            Map.entry("DEVICE", "device"),
            Map.entry("FIRMWARE", "firmware"),
            Map.entry("FILE", "file"),
            Map.entry("SOURCE", "file"),
            Map.entry("ARCHIVE", "file"),
            Map.entry("INSTALL", "application"),
            Map.entry("OTHER", "library"));

    /**
     * The default when SPDX says nothing. {@code packages[]} in a dependency SBOM is overwhelmingly
     * libraries, and a null type would render as a gap in a column CycloneDX documents always fill.
     */
    private static final String DEFAULT_TYPE = "library";

    public NormalizedSbom normalize(SpdxDocument document) {
        Set<String> rootIds = describedElementIds(document);

        NormalizedSbom.NormalizedSbomBuilder builder = NormalizedSbom.builder()
                .format(SbomFormat.SPDX)
                // Verbatim: "SPDX-2.3" identifies both the format and its revision, where CycloneDX
                // splits that across bomFormat + specVersion.
                .specVersion(document.getSpdxVersion())
                // SPDX has no document-revision counter. 1 is "the only revision this file claims".
                .version(1);

        if (document.getPackages() != null) {
            for (SpdxPackage pkg : document.getPackages()) {
                if (pkg == null) {
                    continue;
                }
                NormalizedComponent component = component(pkg);
                if (component.name() == null && component.purl() == null) {
                    continue;
                }
                if (pkg.getSpdxId() != null && rootIds.contains(pkg.getSpdxId())) {
                    // The thing being described is the product, not one of its dependencies.
                    builder.rootComponent(component);
                } else {
                    builder.component(component);
                }
            }
        }

        for (NormalizedSbom.NormalizedTool tool : tools(document)) {
            builder.tool(tool);
        }

        return builder.build();
    }

    /* ------------------------------------------------------------------ */
    /* Root identification                                                */
    /* ------------------------------------------------------------------ */

    /**
     * The SPDXIDs the document describes, from both spellings: the {@code documentDescribes}
     * shorthand and an explicit {@code DESCRIBES} relationship. Producers emit one, the other, or
     * both, so both are read and unioned.
     */
    private Set<String> describedElementIds(SpdxDocument document) {
        Set<String> ids = new LinkedHashSet<>();
        if (document.getDocumentDescribes() != null) {
            for (String id : document.getDocumentDescribes()) {
                if (id != null && !id.isBlank()) {
                    ids.add(id.trim());
                }
            }
        }
        if (document.getRelationships() != null) {
            for (SpdxRelationship relationship : document.getRelationships()) {
                if (relationship == null || !DESCRIBES.equalsIgnoreCase(relationship.getRelationshipType())) {
                    continue;
                }
                String related = relationship.getRelatedSpdxElement();
                if (related != null && !related.isBlank()) {
                    ids.add(related.trim());
                }
            }
        }
        return ids;
    }

    /* ------------------------------------------------------------------ */
    /* Package mapping                                                    */
    /* ------------------------------------------------------------------ */

    private NormalizedComponent component(SpdxPackage pkg) {
        String description = value(pkg.getDescription());
        if (description == null) {
            description = value(pkg.getSummary());
        }
        return NormalizedComponent.builder()
                .name(pkg.getName())
                .version(value(pkg.getVersionInfo()))
                .purl(purl(pkg))
                .type(type(pkg))
                .description(description)
                // SPDX's internal handle. Same role as a CycloneDX bom-ref: provenance, not identity.
                .bomRef(pkg.getSpdxId())
                .licenses(licenses(pkg))
                .externalReferences(references(pkg))
                .hashes(hashes(pkg))
                .build();
    }

    /**
     * SPDX {@code checksums[]} → the normalised digest list. This is the {@code checksums[]} read the
     * class note above anticipated; it needed no {@code files[]} binding after all, because SPDX puts
     * package-level checksums on the package.
     *
     * <p>Note the algorithm spelling differs from CycloneDX's ({@code SHA256} vs {@code SHA-256}) and
     * is stored verbatim-but-upper-cased; {@code ComponentHash.isSha256()} accepts both, so the two
     * parsers converge without either having to know about the other.
     */
    private List<NormalizedComponent.ComponentHashValue> hashes(SpdxPackage pkg) {
        if (pkg.getChecksums() == null) {
            return List.of();
        }
        List<NormalizedComponent.ComponentHashValue> out = new ArrayList<>();
        for (SpdxChecksum checksum : pkg.getChecksums()) {
            if (checksum == null) {
                continue;
            }
            ComponentHash normalized = ComponentHash.of(checksum.getAlgorithm(), checksum.getChecksumValue());
            if (normalized != null) {
                out.add(new NormalizedComponent.ComponentHashValue(
                        normalized.getAlgorithm(), normalized.getValue()));
            }
        }
        return out;
    }

    /** The PURL hides in {@code externalRefs[]} under {@code referenceType: "purl"}. */
    private String purl(SpdxPackage pkg) {
        if (pkg.getExternalRefs() == null) {
            return null;
        }
        for (SpdxExternalRef ref : pkg.getExternalRefs()) {
            if (ref == null || !"purl".equalsIgnoreCase(trim(ref.getReferenceType()))) {
                continue;
            }
            String locator = value(ref.getReferenceLocator());
            if (locator != null) {
                return locator;
            }
        }
        return null;
    }

    private String type(SpdxPackage pkg) {
        String purpose = trim(pkg.getPrimaryPackagePurpose());
        if (purpose == null) {
            return DEFAULT_TYPE;
        }
        return PURPOSES.getOrDefault(purpose.toUpperCase(Locale.ROOT), DEFAULT_TYPE);
    }

    /**
     * {@code licenseConcluded} first (the analyst's verdict), then {@code licenseDeclared} (what the
     * package claims about itself), deduped. Either can be an SPDX license <em>expression</em> such
     * as {@code "(MIT OR Apache-2.0)"}; it is kept verbatim as one identifier rather than split,
     * because splitting an expression on {@code OR} would assert a conjunction the document does not
     * state.
     */
    private List<String> licenses(SpdxPackage pkg) {
        Set<String> out = new LinkedHashSet<>();
        String concluded = value(pkg.getLicenseConcluded());
        if (concluded != null) {
            out.add(concluded);
        }
        String declared = value(pkg.getLicenseDeclared());
        if (declared != null) {
            out.add(declared);
        }
        return new ArrayList<>(out);
    }

    /** Everything in {@code externalRefs[]} bar the PURL, which is promoted to its own field. */
    private List<NormalizedComponent.ExternalReference> references(SpdxPackage pkg) {
        if (pkg.getExternalRefs() == null) {
            return List.of();
        }
        List<NormalizedComponent.ExternalReference> out = new ArrayList<>();
        for (SpdxExternalRef ref : pkg.getExternalRefs()) {
            if (ref == null || "purl".equalsIgnoreCase(trim(ref.getReferenceType()))) {
                continue;
            }
            String locator = value(ref.getReferenceLocator());
            if (locator != null) {
                out.add(new NormalizedComponent.ExternalReference(trim(ref.getReferenceType()), locator));
            }
        }
        return out;
    }

    /* ------------------------------------------------------------------ */
    /* Tools                                                              */
    /* ------------------------------------------------------------------ */

    /**
     * {@code creationInfo.creators[]} entries prefixed {@code "Tool:"}. The SPDX convention is
     * {@code "Tool: <name>-<version>"}, so the last hyphen-separated segment is taken as the version
     * when it starts with a digit — and left alone when it does not, so a tool genuinely named
     * {@code "cyclonedx-gomod"} is not truncated.
     */
    private List<NormalizedSbom.NormalizedTool> tools(SpdxDocument document) {
        if (document.getCreationInfo() == null || document.getCreationInfo().getCreators() == null) {
            return List.of();
        }
        List<NormalizedSbom.NormalizedTool> out = new ArrayList<>();
        for (String creator : document.getCreationInfo().getCreators()) {
            String trimmed = trim(creator);
            if (trimmed == null || !trimmed.regionMatches(true, 0, "Tool:", 0, 5)) {
                continue;
            }
            String spec = trim(trimmed.substring(5));
            if (spec == null) {
                continue;
            }
            String name = spec;
            String version = null;
            int hyphen = spec.lastIndexOf('-');
            if (hyphen > 0 && hyphen + 1 < spec.length() && Character.isDigit(spec.charAt(hyphen + 1))) {
                name = spec.substring(0, hyphen);
                version = spec.substring(hyphen + 1);
            }
            out.add(new NormalizedSbom.NormalizedTool(name, version, null, "application"));
        }
        return out;
    }

    /* ------------------------------------------------------------------ */

    private static String trim(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /** Trimmed, with SPDX's {@code NOASSERTION} / {@code NONE} sentinels read as absent. */
    private static String value(String raw) {
        String trimmed = trim(raw);
        return trimmed == null || NO_VALUE.contains(trimmed.toUpperCase(Locale.ROOT)) ? null : trimmed;
    }

}
