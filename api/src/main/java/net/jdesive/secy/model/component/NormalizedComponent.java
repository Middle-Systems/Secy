package net.jdesive.secy.model.component;

import lombok.Builder;
import lombok.Singular;
import net.jdesive.secy.correlation.ComponentCoordinate;

import java.util.List;

/**
 * One dependency, in the single shape the rest of Secy understands.
 *
 * <p>Both SBOM parsers produce this and nothing else; {@code SBOMService} is the only thing that
 * turns it into a persisted {@code SBOMComponent}, and the scan pipeline
 * ({@code VulnerabilityScanner} → {@code AlertService} → {@code CorrelationService}) never learns
 * which format the document arrived in.
 *
 * <h2>Why a record and not an entity</h2>
 *
 * <p>This is a <em>parse target</em>, not a storage model. {@code SBOMComponent} is already the
 * persisted component — it carries the {@code VulnerabilityAlert} FK, the license and reference child
 * tables, and the JSON shape the UI reads. Promoting {@code NormalizedComponent} to an entity would
 * mean either a second component table with the same rows in it or a migration of every alert FK, for
 * no gain: the two models have different lifetimes (one lives for the duration of a request, the
 * other forever) and different fields (the entity has an id, a parent SBOM and an identity key; the
 * record has a format-native {@code bomRef} and a derived ecosystem). Keeping the parse target
 * immutable and free of JPA is what lets the parsers be unit-tested with no Spring context.
 *
 * @param name               ecosystem-native package name as the document spells it
 * @param version            the declared version, or null (SPDX {@code NOASSERTION} is normalised away)
 * @param purl               package URL, or null — CycloneDX {@code purl} / an SPDX {@code externalRefs[]}
 *                           entry with {@code referenceType: "purl"}
 * @param ecosystem          OSV ecosystem derived from the PURL type, or null — see {@link #ecosystemOf}
 * @param type               {@code library} / {@code application} / {@code framework} / … CycloneDX states
 *                           it directly; SPDX only approximates it from {@code primaryPackagePurpose} (2.3)
 * @param description        free text, or null
 * @param licenses           license identifiers or SPDX license expressions, in document order, deduped
 * @param externalReferences links the document carried for this component
 * @param bomRef             the document's own internal handle — CycloneDX {@code bom-ref}, SPDX {@code SPDXID}.
 *                           Provenance only; it is <b>not</b> stable across uploads and must never be
 *                           used as an identity (that is {@link ComponentIdentity}'s job)
 * @param hashes             digests the document declared — CycloneDX {@code hashes[]}, SPDX
 *                           {@code checksums[]} — already normalised by
 *                           {@link net.jdesive.secy.persistence.entity.ComponentHash#of}. Usually
 *                           empty; Phase 6 matches the SHA-256 entry against the malware-hash corpus.
 *                           Malformed entries are dropped by the normaliser rather than stored
 */
@Builder
public record NormalizedComponent(String name,
                                  String version,
                                  String purl,
                                  String ecosystem,
                                  String type,
                                  String description,
                                  @Singular List<String> licenses,
                                  @Singular List<ExternalReference> externalReferences,
                                  String bomRef,
                                  @Singular List<ComponentHashValue> hashes) {

    /** A link the source document carried for a component. */
    public record ExternalReference(String type, String url) {
    }

    /**
     * One declared digest, in the format-neutral shape.
     *
     * <p>A record rather than the {@code ComponentHash} entity for the same reason this whole class
     * is a record and not an entity: it is a parse target with a request-scoped lifetime, and
     * binding JPA into the parsers is what keeps them from being unit-testable with no Spring
     * context. {@code SBOMService} converts.
     */
    public record ComponentHashValue(String algorithm, String value) {
    }

    public NormalizedComponent {
        name = trimToNull(name);
        version = trimToNull(version);
        purl = trimToNull(purl);
        ecosystem = trimToNull(ecosystem);
        type = trimToNull(type);
        description = trimToNull(description);
        licenses = licenses == null ? List.of() : List.copyOf(licenses);
        externalReferences = externalReferences == null ? List.of() : List.copyOf(externalReferences);
        hashes = hashes == null ? List.of() : List.copyOf(hashes);
        bomRef = trimToNull(bomRef);

        // Derived, never supplied: a parser that guessed its own ecosystem could disagree with the
        // one correlation derives from the same PURL, and the mismatch would be invisible.
        if (purl != null) {
            ecosystem = ecosystemOf(purl, name);
        }
    }

    /**
     * The identity this component carries forward across SBOM versions of its product.
     *
     * @see ComponentIdentity
     */
    public String identityKey() {
        return ComponentIdentity.keyOf(purl, name);
    }

    /** The OSV ecosystem a PURL implies, or null when OSV does not index that PURL type. */
    public static String ecosystemOf(String purl, String name) {
        return ComponentCoordinate.of(purl, name, null).ecosystem();
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

}
