package net.jdesive.secy.service.sbom;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.component.DependencyEdgeCollector;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.component.SbomFormat;
import net.jdesive.secy.model.component.SecondaryIdentifiers;
import net.jdesive.secy.model.spdx.SpdxChecksum;
import net.jdesive.secy.model.spdx.SpdxCreationInfo;
import net.jdesive.secy.model.spdx.SpdxDocument;
import net.jdesive.secy.model.spdx.SpdxExternalRef;
import net.jdesive.secy.model.spdx.SpdxPackage;
import net.jdesive.secy.model.spdx.SpdxRelationship;
import net.jdesive.secy.persistence.entity.ComponentHash;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
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
 *
 * <h2>M1h: dependency-relationship graph — presence only</h2>
 *
 * <p>{@link #dependencyRefs} reads a fixed set of relationship types purely to record which
 * SPDXIDs take part in <em>at least one</em> declared dependency relationship — for
 * {@code SbomQualityScorer}'s NTIA completeness check. This is still not a graph traversal: no
 * edges are stored, no tree is built, nothing here changes the "relationship graph is not
 * traversed" statement above for correlation purposes.
 *
 * <h2>M1l: directed dependency edges — a narrower set of types</h2>
 *
 * <p>{@link #dependencyEdges} reads only {@code DEPENDS_ON} and the seven {@code *_DEPENDENCY_OF}
 * types (never the other six {@link #DEPENDENCY_RELATIONSHIP_TYPES} entries) to build a directed
 * edge list for {@code DependencyGraphAnalyzer}'s BFS classification. {@code CONTAINS}/{@code
 * CONTAINED_BY} are deliberately excluded here: a Syft-style document declares {@code root CONTAINS
 * <every package>} flatly alongside any real dependency edges, and counting it would make every
 * component DIRECT, erasing the transitive signal entirely. Correlation itself remains a flat-set
 * operation over {@code packages[]} — this still does not change that.
 */
@Slf4j
@Component
public class SpdxNormalizer {

    /** SPDX sentinels that mean "no information", not a value. */
    private static final Set<String> NO_VALUE = Set.of("NOASSERTION", "NONE");

    private static final String DESCRIBES = "DESCRIBES";

    /**
     * Relationship types M1h treats as a declared dependency edge, for presence-only scoring. Both
     * ends of a matching relationship count. {@code DESCRIBES}/{@code DESCRIBED_BY} are deliberately
     * excluded — they identify the root, not a dependency.
     */
    private static final Set<String> DEPENDENCY_RELATIONSHIP_TYPES = Set.of(
            "DEPENDS_ON", "DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF",
            "OPTIONAL_DEPENDENCY_OF", "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF", "DEPENDENCY_MANIFEST_OF",
            "CONTAINS", "CONTAINED_BY", "STATIC_LINK", "DYNAMIC_LINK", "PREREQUISITE_FOR", "HAS_PREREQUISITE");

    /**
     * M1l: {@code spdxElementId -> relatedSpdxElement} (A -> B) edges — the one SPDX relationship
     * type whose declared direction already matches "A depends on B".
     */
    private static final Set<String> FORWARD_DEPENDENCY_TYPES = Set.of("DEPENDS_ON");

    /**
     * M1l: {@code relatedSpdxElement -> spdxElementId} (B -> A) edges — these seven types are all
     * phrased "A is a dependency OF B", so the dependency edge runs the other way from the
     * relationship's own A/B order.
     */
    private static final Set<String> REVERSE_DEPENDENCY_TYPES = Set.of(
            "DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF",
            "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF");

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

        // TODO(spdx-3): SPDX 2.2/2.3 has no lifecycle-stage equivalent to CycloneDX's
        // metadata.lifecycles[] (M1e) — declaredLifecycleStage stays null (the builder default) for
        // every SPDX document. SPDX 3.x's software_Sbom.sbomType may supply one; out of scope here.

        // M1h: document-declared timestamp/authors, and dependency-relationship presence.
        SpdxCreationInfo creationInfo = document.getCreationInfo();
        if (creationInfo != null) {
            builder.documentTimestamp(timestamp(creationInfo.getCreated()));
        }
        builder.authors(authors(document));
        builder.dependencyRelationshipRefs(dependencyRefs(document));

        // M1l: directed dependency edges (a narrower type set than dependencyRefs above) and the
        // document's own root refs — see this class's Javadoc and NormalizedSbom's field docs.
        DependencyEdgeCollector collector = new DependencyEdgeCollector();
        collectDependencyEdges(document, collector);
        if (collector.overflowed()) {
            log.warn("SPDX document declared too many dependency edges — discarding the whole "
                    + "dependency graph; every component will classify as UNKNOWN depth");
        }
        builder.dependencyEdges(collector.edges());
        builder.dependencyRootRefs(rootIds);

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
                .identifiers(identifiers(pkg))
                .supplier(party(pkg.getSupplier()))
                .build();
    }

    /**
     * SPDX {@code PackageSupplier} (M1h) — {@code value()} first (drops {@code NOASSERTION}/
     * {@code NONE}), then strips a leading {@code Organization:}/{@code Person:} prefix
     * case-insensitively and trims. Null when absent or a sentinel.
     */
    private static String party(String raw) {
        String withPrefix = value(raw);
        if (withPrefix == null) {
            return null;
        }
        String stripped = stripPartyPrefix(withPrefix);
        return stripped == null || stripped.isBlank() ? null : stripped.trim();
    }

    private static String stripPartyPrefix(String value) {
        if (value.regionMatches(true, 0, "Organization:", 0, 13)) {
            return value.substring(13);
        }
        if (value.regionMatches(true, 0, "Person:", 0, 7)) {
            return value.substring(7);
        }
        return value;
    }

    /**
     * SPDX {@code externalRefs[].cpe23Type}/{@code cpe22Type}/{@code swid} (M1c) → the normalised
     * identifier list. Deliberately promoted <b>in addition to</b>, not instead of, the same refs
     * staying in {@link #references} — the roadmap's "SPDX CPE/SWID refs stay in
     * {@code sbom_reference} too" decision, so the UI's existing references list is unaffected. An
     * SPDX {@code swid} ref carries only a tagId (no name/version), which
     * {@code ComponentIdentityAssessor} accounts for when assessing it.
     */
    private List<NormalizedComponent.Identifier> identifiers(SpdxPackage pkg) {
        if (pkg.getExternalRefs() == null) {
            return List.of();
        }
        List<NormalizedComponent.Identifier> out = new ArrayList<>();
        for (SpdxExternalRef ref : pkg.getExternalRefs()) {
            if (ref == null) {
                continue;
            }
            String type = trim(ref.getReferenceType());
            String locator = value(ref.getReferenceLocator());
            if (type == null || locator == null) {
                continue;
            }
            NormalizedComponent.Identifier identifier = null;
            if ("cpe23Type".equalsIgnoreCase(type)) {
                identifier = SecondaryIdentifiers.cpe(locator, SecondaryIdentifiers.SPDX_CPE23);
            } else if ("cpe22Type".equalsIgnoreCase(type)) {
                identifier = SecondaryIdentifiers.cpe(locator, SecondaryIdentifiers.SPDX_CPE22);
            } else if ("swid".equalsIgnoreCase(type)) {
                identifier = SecondaryIdentifiers.swid(locator, null, null, SecondaryIdentifiers.SPDX_SWID);
            }
            if (identifier != null) {
                out.add(identifier);
            }
        }
        return SecondaryIdentifiers.dedupe(out);
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

    /**
     * {@code creationInfo.creators[]} entries prefixed {@code Person:}/{@code Organization:} (M1h) —
     * who created the SBOM DATA. {@code Tool:} entries never count as an author, unlike
     * {@link #tools(SpdxDocument)}, which reads only those.
     */
    private static List<String> authors(SpdxDocument document) {
        if (document.getCreationInfo() == null || document.getCreationInfo().getCreators() == null) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String creator : document.getCreationInfo().getCreators()) {
            String trimmed = trim(creator);
            if (trimmed == null) {
                continue;
            }
            String rest = null;
            if (trimmed.regionMatches(true, 0, "Person:", 0, 7)) {
                rest = trimmed.substring(7);
            } else if (trimmed.regionMatches(true, 0, "Organization:", 0, 13)) {
                rest = trimmed.substring(13);
            }
            String value = trim(rest);
            if (value != null) {
                out.add(value.length() > 255 ? value.substring(0, 255) : value);
            }
        }
        return out;
    }

    /**
     * SPDX {@code creationInfo.created} (M1h) — the document's own declared creation time. Tolerates
     * both an offset (RFC 3339, the SPDX-mandated shape) and a bare local date-time; unparseable
     * degrades to null (logged at DEBUG) rather than failing the upload. A private copy of the same
     * pattern {@code VexParsing.timestamp} uses, kept local rather than made public just for this one
     * caller.
     */
    private static LocalDateTime timestamp(String raw) {
        String trimmed = trim(raw);
        if (trimmed == null) {
            return null;
        }
        try {
            return OffsetDateTime.parse(trimmed).atZoneSameInstant(ZoneId.systemDefault()).toLocalDateTime();
        } catch (DateTimeParseException offsetFailure) {
            try {
                return LocalDateTime.parse(trimmed);
            } catch (DateTimeParseException localFailure) {
                log.debug("Unparseable SPDX creationInfo.created: '{}'", raw);
                return null;
            }
        }
    }

    /**
     * {@code relationships[]} entries whose {@code relationshipType} is one of
     * {@link #DEPENDENCY_RELATIONSHIP_TYPES} (M1h) — both {@code spdxElementId} and
     * {@code relatedSpdxElement} are added, trimmed and non-blank. A literal {@code NONE}/
     * {@code NOASSERTION} target is added harmlessly (it never matches a real SPDXID); its source
     * package still counts, per NTIA's "known unknowns" guidance. {@code DESCRIBES}/
     * {@code DESCRIBED_BY} are excluded — they identify the root, not a dependency edge.
     */
    private static Set<String> dependencyRefs(SpdxDocument document) {
        Set<String> out = new LinkedHashSet<>();
        if (document.getRelationships() == null) {
            return out;
        }
        for (SpdxRelationship relationship : document.getRelationships()) {
            if (relationship == null || relationship.getRelationshipType() == null) {
                continue;
            }
            String type = relationship.getRelationshipType().trim().toUpperCase(Locale.ROOT);
            if (!DEPENDENCY_RELATIONSHIP_TYPES.contains(type)) {
                continue;
            }
            String source = trim(relationship.getSpdxElementId());
            if (source != null) {
                out.add(source);
            }
            String target = trim(relationship.getRelatedSpdxElement());
            if (target != null) {
                out.add(target);
            }
        }
        return out;
    }

    /**
     * {@code relationships[]} entries whose {@code relationshipType} is {@code DEPENDS_ON} or one of
     * the seven {@code *_DEPENDENCY_OF} types (M1l) — see this class's Javadoc and {@link
     * #FORWARD_DEPENDENCY_TYPES}/{@link #REVERSE_DEPENDENCY_TYPES} for the direction table. Either
     * end being null/blank/{@code NONE}/{@code NOASSERTION} (case-insensitively, via {@link #value})
     * drops the edge entirely rather than keeping a one-sided fragment. {@code CONTAINS}/{@code
     * CONTAINED_BY}/{@code DEPENDENCY_MANIFEST_OF}/{@code STATIC_LINK}/{@code DYNAMIC_LINK}/{@code
     * PREREQUISITE_FOR}/{@code HAS_PREREQUISITE}/{@code DESCRIBES}/{@code DESCRIBED_BY} never become
     * edges here, even though several of them are in {@link #DEPENDENCY_RELATIONSHIP_TYPES} for the
     * unrelated M1h presence check.
     */
    private static void collectDependencyEdges(SpdxDocument document, DependencyEdgeCollector collector) {
        if (document.getRelationships() == null) {
            return;
        }
        for (SpdxRelationship relationship : document.getRelationships()) {
            if (relationship == null || relationship.getRelationshipType() == null) {
                continue;
            }
            String type = relationship.getRelationshipType().trim().toUpperCase(Locale.ROOT);
            String a = value(relationship.getSpdxElementId());
            String b = value(relationship.getRelatedSpdxElement());
            if (a == null || b == null) {
                continue;
            }
            if (FORWARD_DEPENDENCY_TYPES.contains(type)) {
                collector.add(a, b);
            } else if (REVERSE_DEPENDENCY_TYPES.contains(type)) {
                collector.add(b, a);
            }
        }
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
