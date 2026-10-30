package net.jdesive.secy.service.sbom;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.component.ComponentIdentityAssessor;
import net.jdesive.secy.model.component.ComponentIdentityResponse;
import net.jdesive.secy.model.component.ComponentProvenance;
import net.jdesive.secy.persistence.SBOMComponentIdentityConflictRepository;
import net.jdesive.secy.persistence.SBOMComponentRepository;
import net.jdesive.secy.persistence.entity.ComponentHash;
import net.jdesive.secy.persistence.entity.IdentityConfidence;
import net.jdesive.secy.persistence.entity.IdentityConflictType;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SBOMComponentIdentityConflict;
import net.jdesive.secy.persistence.entity.SecondaryIdentifierType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * M1c's cross-instance identity work (ROADMAP.md — "Canonical component identity"): Pass B of
 * identity checking — the tenant-wide content-hash collision sweep that {@code ComponentIdentityAssessor}
 * (Pass A, within one component instance) cannot do on its own — plus the read side of the identity
 * API, {@link #describe}.
 *
 * <h2>Why this needs the database and {@code ComponentIdentityAssessor} does not</h2>
 *
 * <p>Pass A only ever looks at one component's own declared identifiers — a pure function, no I/O.
 * "Does this digest also appear on a component with a different identity, somewhere else in the
 * tenant" is a different kind of question: it can only be answered by querying every other
 * {@code sbom_component} in the tenant, including ones from SBOMs uploaded long before this one.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ComponentIdentityService {

    /** Batch size for the {@code IN (:values)} lookup — keeps the query well under typical parameter-count limits. */
    private static final int CHUNK_SIZE = 1000;

    /**
     * Strong, collision-resistant digest algorithms worth cross-checking identity on (canonicalised:
     * upper-cased, {@code -}/{@code _} stripped). MD5/SHA-1 are deliberately excluded — a match on
     * either proves nothing given how easy both are to collide on purpose.
     */
    private static final Set<String> STRONG_ALGORITHMS = Set.of(
            "SHA256", "SHA384", "SHA512", "SHA3256", "SHA3384", "SHA3512",
            "BLAKE2B256", "BLAKE2B384", "BLAKE2B512", "BLAKE3");

    /**
     * The empty-input digest under each strong algorithm above that has one in common use. An empty
     * file/artifact hashes the same everywhere and would otherwise "collide" every empty component in
     * the tenant with every other one — noise, not a finding.
     */
    private static final Set<String> EMPTY_CONTENT_DIGESTS = Set.of(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

    private final SBOMComponentRepository componentRepository;
    private final SBOMComponentIdentityConflictRepository conflictRepository;

    /** One of this SBOM's own components, plus which of its digests are worth checking, keyed by canonical algorithm. */
    private record OwnHolder(SBOMComponent component, String canonicalAlgorithm) {
    }

    /**
     * Sweep every strong digest declared on {@code sbom}'s components against the rest of the tenant.
     * REQUIRED propagation — joins the ingest transaction {@code SBOMService#ingestDocument} already
     * has open, so a component flagged here and one flagged by Pass A in the same call both land in
     * the same commit.
     *
     * @return how many distinct (component, other component, algorithm, digest) collisions were found
     */
    @Transactional
    public int flagHashIdentityCollisions(SBOM sbom) {
        List<SBOMComponent> components = new ArrayList<>(sbom.getComponents());
        if (sbom.getComponent() != null) {
            components.add(sbom.getComponent());
        }

        Set<UUID> ownComponentIds = new HashSet<>();
        Map<String, List<OwnHolder>> ownHoldersByDigest = new LinkedHashMap<>();
        for (SBOMComponent component : components) {
            if (component.getId() == null || component.getIdentityKey() == null) {
                continue;
            }
            ownComponentIds.add(component.getId());
            for (ComponentHash hash : component.getHashes()) {
                String canonical = ComponentIdentityAssessor.canonicalAlgorithm(hash.getAlgorithm());
                if (canonical == null || !STRONG_ALGORITHMS.contains(canonical)
                        || EMPTY_CONTENT_DIGESTS.contains(hash.getValue())) {
                    continue;
                }
                ownHoldersByDigest.computeIfAbsent(hash.getValue(), k -> new ArrayList<>())
                        .add(new OwnHolder(component, canonical));
            }
        }
        if (ownHoldersByDigest.isEmpty()) {
            return 0;
        }

        List<String> values = new ArrayList<>(ownHoldersByDigest.keySet());
        Set<String> seenPairs = new LinkedHashSet<>();
        Set<UUID> otherIdsOutsideThisSbom = new LinkedHashSet<>();
        int pairCount = 0;

        for (int i = 0; i < values.size(); i += CHUNK_SIZE) {
            List<String> chunk = values.subList(i, Math.min(values.size(), i + CHUNK_SIZE));
            List<Object[]> rows = componentRepository.findHashHoldersInTenant(sbom.getTenantId(), chunk);
            for (Object[] row : rows) {
                UUID otherId = (UUID) row[0];
                String otherKey = (String) row[1];
                String otherCanonical = ComponentIdentityAssessor.canonicalAlgorithm((String) row[2]);
                String otherValue = (String) row[3];
                if (otherCanonical == null || !STRONG_ALGORITHMS.contains(otherCanonical)) {
                    continue;
                }

                for (OwnHolder own : ownHoldersByDigest.getOrDefault(otherValue, List.of())) {
                    SBOMComponent ownComponent = own.component();
                    if (ownComponent.getId().equals(otherId)
                            || !own.canonicalAlgorithm().equals(otherCanonical)
                            || ownComponent.getIdentityKey().equals(otherKey)) {
                        continue;
                    }

                    String pairKey = ownComponent.getId() + "|" + otherId + "|" + otherCanonical + "|" + otherValue;
                    if (!seenPairs.add(pairKey)) {
                        continue;
                    }
                    pairCount++;

                    String detail = "Same " + otherCanonical + " digest declared on identity '"
                            + ownComponent.getIdentityKey() + "' and identity '" + otherKey + "'";

                    SBOMComponentIdentityConflict ownConflict = new SBOMComponentIdentityConflict();
                    ownConflict.setComponent(ownComponent);
                    ownConflict.setConflictType(IdentityConflictType.HASH_IDENTITY_COLLISION);
                    ownConflict.setIdentifierType(SecondaryIdentifierType.HASH);
                    ownConflict.setIdentifierValue(otherCanonical + ":" + otherValue);
                    ownConflict.setOtherComponentId(otherId);
                    ownConflict.setOtherIdentityKey(otherKey);
                    ownConflict.setDetail(detail);
                    ownConflict.setDetectedAt(LocalDateTime.now());
                    ownComponent.getIdentityConflicts().add(ownConflict);
                    ownComponent.setIdentityConfidence(IdentityConfidence.CONFLICTING);

                    if (!ownComponentIds.contains(otherId)) {
                        SBOMComponentIdentityConflict mirror = new SBOMComponentIdentityConflict();
                        mirror.setComponent(componentRepository.getReferenceById(otherId));
                        mirror.setConflictType(IdentityConflictType.HASH_IDENTITY_COLLISION);
                        mirror.setIdentifierType(SecondaryIdentifierType.HASH);
                        mirror.setIdentifierValue(otherCanonical + ":" + otherValue);
                        mirror.setOtherComponentId(ownComponent.getId());
                        mirror.setOtherIdentityKey(ownComponent.getIdentityKey());
                        mirror.setDetail(detail);
                        mirror.setDetectedAt(LocalDateTime.now());
                        conflictRepository.save(mirror);
                        otherIdsOutsideThisSbom.add(otherId);
                    }
                }
            }
        }

        if (!otherIdsOutsideThisSbom.isEmpty()) {
            componentRepository.markIdentityConfidence(otherIdsOutsideThisSbom, IdentityConfidence.CONFLICTING);
        }

        if (pairCount > 0) {
            log.info("SBOM {}: flagged {} hash-identity collision(s) across {} other component(s) outside it",
                    sbom.getId(), pairCount, otherIdsOutsideThisSbom.size());
        }
        return pairCount;
    }

    /** {@code GET /sbom/{sbomId}/components/{componentId}/identity}. */
    @Transactional(readOnly = true)
    public ComponentIdentityResponse describe(UUID sbomId, UUID componentId) {
        SBOMComponent component = componentRepository.findByIdAndSbomId(componentId, sbomId)
                .orElseThrow(() -> new ComponentNotFoundException(
                        "No component " + componentId + " in SBOM " + sbomId));

        List<ComponentIdentityResponse.IdentifierView> identifiers = component.getIdentifiers().stream()
                .map(i -> new ComponentIdentityResponse.IdentifierView(
                        i.getIdentifierType(), i.getIdentifierValue(), i.getDeclaredName(),
                        i.getDeclaredVersion(), i.getSource()))
                .toList();

        List<ComponentIdentityResponse.HashView> hashes = component.getHashes().stream()
                .map(h -> new ComponentIdentityResponse.HashView(h.getAlgorithm(), h.getValue()))
                .toList();

        List<ComponentIdentityResponse.ConflictView> conflicts = component.getIdentityConflicts().stream()
                .map(c -> new ComponentIdentityResponse.ConflictView(
                        c.getConflictType(), c.getIdentifierType(), c.getIdentifierValue(),
                        c.getOtherComponentId(), c.getOtherIdentityKey(), c.getDetail(), c.getDetectedAt()))
                .toList();

        return new ComponentIdentityResponse(
                component.getId(), sbomId, component.getName(), component.getVersion(), component.getPurl(),
                component.getIdentityKey(), component.getIdentityConfidence(),
                identifiers, hashes, conflicts, ComponentProvenance.of(component));
    }

}
