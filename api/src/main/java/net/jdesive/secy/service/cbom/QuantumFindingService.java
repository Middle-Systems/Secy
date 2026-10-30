package net.jdesive.secy.service.cbom;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.SbomCorrelationScope;
import net.jdesive.secy.model.cbom.VulnerableCryptoRow;
import net.jdesive.secy.persistence.QuantumVulnerabilityFindingRepository;
import net.jdesive.secy.persistence.SBOMComponentCryptoAssetRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.QuantumClassificationBasis;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityFinding;
import net.jdesive.secy.persistence.entity.QuantumVulnerableFamily;
import net.jdesive.secy.persistence.entity.SBOM;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The Spring/JPA half of M1g's quantum-vulnerability finding engine: for one SBOM that just landed,
 * find every {@code VULNERABLE} crypto asset in its correlation scope and reconcile
 * {@link QuantumVulnerabilityFinding} rows against it. Triggered by {@link QuantumFindingListener}
 * after every relevant SBOM upload commits — see that class for why after-commit rather than inline.
 * Modeled directly on {@code LifecycleDiffService}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class QuantumFindingService {

    private final SBOMRepository sbomRepository;
    private final SBOMComponentCryptoAssetRepository cryptoAssetRepository;
    private final QuantumVulnerabilityFindingRepository findingRepository;
    private final SbomCorrelationScope sbomCorrelationScope;

    /** What one {@link #reconcileForSbom} call did. Returned for logging/tests. */
    public record QuantumReconcileSummary(int created, int updated, int autoResolved) {
        static final QuantumReconcileSummary EMPTY = new QuantumReconcileSummary(0, 0, 0);
    }

    /**
     * Reconcile {@code sbomId}'s scope against {@link QuantumVulnerabilityFinding}, in a fresh
     * transaction — {@code REQUIRES_NEW} for the same reason as {@code LifecycleDiffService.runForSbom}:
     * a concurrent duplicate insert on the unique partial index rolls back only the loser.
     *
     * <p>Skipped entirely (empty summary, DEBUG log) when the SBOM does not exist, is not
     * {@code active} (a newer upload runs its own reconcile), or has no product.
     *
     * <p><b>Bucket SBOMs are supported here</b> — unlike {@code LifecycleDiffService}, which skips the
     * Unassigned bucket entirely, a security finding must not vanish just because an upload was
     * untagged; bucket SBOMs are reconciled per-SBOM ({@code scope_sbom_id} set) instead of per-product.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public QuantumReconcileSummary reconcileForSbom(UUID sbomId) {
        SBOM sbom = sbomRepository.findById(sbomId).orElse(null);
        if (sbom == null) {
            log.debug("Quantum finding reconciliation skipped: SBOM {} not found", sbomId);
            return QuantumReconcileSummary.EMPTY;
        }
        if (!sbom.isActive()) {
            log.debug("Quantum finding reconciliation skipped: SBOM {} is no longer active (superseded)", sbomId);
            return QuantumReconcileSummary.EMPTY;
        }
        if (sbom.getProduct() == null) {
            log.debug("Quantum finding reconciliation skipped: SBOM {} has no product", sbomId);
            return QuantumReconcileSummary.EMPTY;
        }

        boolean productScoped = !sbom.getProduct().isUnassigned();
        UUID productId = sbom.getProduct().getId();

        List<SBOM> scope = sbomCorrelationScope.sbomsInScope(sbom, productScoped);
        Map<UUID, Integer> scopeIndex = new LinkedHashMap<>();
        List<UUID> scopeIds = new ArrayList<>(scope.size());
        for (SBOM scoped : scope) {
            scopeIndex.put(scoped.getId(), scopeIndex.size());
            scopeIds.add(scoped.getId());
        }

        List<VulnerableCryptoRow> rows = new ArrayList<>(cryptoAssetRepository.findVulnerableInSboms(scopeIds));
        // Ascending by scope order (upstream first), so a plain put() below gives "most-downstream
        // stage wins" for a shared crypto identity — the same rule CorrelationService/LifecycleDiffService use.
        rows.sort((a, b) -> Integer.compare(
                scopeIndex.getOrDefault(a.sbomId(), Integer.MAX_VALUE),
                scopeIndex.getOrDefault(b.sbomId(), Integer.MAX_VALUE)));

        Map<String, VulnerableCryptoRow> candidates = new LinkedHashMap<>();
        for (VulnerableCryptoRow row : rows) {
            if (row.cryptoIdentityKey() != null) {
                candidates.put(row.cryptoIdentityKey(), row);
            }
        }

        List<QuantumVulnerabilityFinding> prior = productScoped
                ? findingRepository.findAllByProductIdAndScopeSbomIdIsNull(productId)
                : findingRepository.findAllByScopeSbomId(sbomId);
        Map<String, QuantumVulnerabilityFinding> existing = new LinkedHashMap<>();
        for (QuantumVulnerabilityFinding finding : prior) {
            existing.putIfAbsent(finding.getCryptoIdentityKey(), finding);
        }

        LocalDateTime now = LocalDateTime.now();
        List<QuantumVulnerabilityFinding> toSave = new ArrayList<>();
        int created = 0;
        int updated = 0;

        for (Map.Entry<String, VulnerableCryptoRow> entry : candidates.entrySet()) {
            String key = entry.getKey();
            VulnerableCryptoRow row = entry.getValue();

            QuantumVulnerabilityFinding finding = existing.get(key);
            if (finding == null) {
                finding = new QuantumVulnerabilityFinding();
                finding.setTenantId(sbom.getTenantId());
                finding.setProductId(productId);
                finding.setScopeSbomId(productScoped ? null : sbomId);
                finding.setCryptoIdentityKey(key);
                created++;
            } else {
                updated++;
            }

            finding.setAssetType(row.assetType());
            finding.setAlgorithmFamily(row.family());
            finding.setClassificationBasis(row.basis());
            finding.setMatchedIndicator(truncate(row.indicator(), 255));
            finding.setDeclaredNistQuantumLevel(row.declaredNistQuantumLevel());
            finding.setComponentName(truncate(row.componentName(), 255));
            finding.setBomRef(truncate(row.bomRef(), 255));
            finding.setSbomId(row.sbomId());
            finding.setComponentId(row.componentId());
            finding.setCryptoAssetId(row.cryptoAssetId());
            finding.setSummary(truncate(summaryFor(row), 1024));
            finding.setLifecycleState(AlertLifecycleState.ACTIVE);
            finding.setLastSeenAt(now);

            toSave.add(finding);
        }

        int autoResolved = 0;
        for (Map.Entry<String, QuantumVulnerabilityFinding> entry : existing.entrySet()) {
            if (candidates.containsKey(entry.getKey())) {
                continue;
            }
            QuantumVulnerabilityFinding stale = entry.getValue();
            if (stale.getLifecycleState() == AlertLifecycleState.AUTO_RESOLVED) {
                continue;
            }
            stale.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            toSave.add(stale);
            autoResolved++;
        }

        if (!toSave.isEmpty()) {
            findingRepository.saveAll(toSave);
        }

        QuantumReconcileSummary summary = new QuantumReconcileSummary(created, updated, autoResolved);
        log.info("Quantum finding reconciliation for SBOM {} (product {}, scope {}): {}", sbomId, productId,
                productScoped ? "product" : "sbom", summary);
        return summary;
    }

    /* ------------------------------------------------------------------ */
    /* Summary text                                                        */
    /* ------------------------------------------------------------------ */

    private static String summaryFor(VulnerableCryptoRow row) {
        String name = row.componentName() != null ? row.componentName() : row.cryptoIdentityKey();
        String typeLabel = assetTypeLabel(row.assetType());
        String familyClause = familyClause(row.family());

        StringBuilder sb = new StringBuilder();
        sb.append(name).append(" (").append(typeLabel).append(") relies on ").append(familyClause)
                .append(", which Shor's algorithm breaks on a cryptographically relevant quantum computer.");

        String primitive = row.primitive();
        boolean signature = "signature".equals(primitive);
        boolean keyExchange = primitive != null
                && (primitive.equals("pke") || primitive.equals("key-agree") || primitive.equals("kem"));
        if (signature) {
            sb.append(" Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).");
        } else if (keyExchange) {
            sb.append(" Plan migration to ML-KEM (FIPS 203), e.g. via a hybrid key exchange.");
        } else {
            sb.append(" Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).");
            sb.append(" Plan migration to ML-KEM (FIPS 203), e.g. via a hybrid key exchange.");
        }

        if (row.assetType() == net.jdesive.secy.persistence.entity.CryptoAssetType.CERTIFICATE) {
            sb.append(" Re-issue under a post-quantum or hybrid signature algorithm when your PKI supports it.");
        }

        if (row.declaredNistQuantumLevel() != null && row.declaredNistQuantumLevel() >= 1
                && (row.basis() == QuantumClassificationBasis.NAME || row.basis() == QuantumClassificationBasis.OID)) {
            sb.append(" The document declares NIST quantum security level ").append(row.declaredNistQuantumLevel())
                    .append(" for it, which contradicts its algorithm family.");
        }

        return sb.toString();
    }

    private static String assetTypeLabel(net.jdesive.secy.persistence.entity.CryptoAssetType assetType) {
        if (assetType == null) {
            return "crypto asset";
        }
        return switch (assetType) {
            case ALGORITHM -> "algorithm";
            case CERTIFICATE -> "certificate";
            case PROTOCOL -> "protocol";
            case RELATED_CRYPTO_MATERIAL -> "key material";
            case UNKNOWN -> "crypto asset";
        };
    }

    private static String familyClause(QuantumVulnerableFamily family) {
        if (family == null) {
            return "a public-key algorithm the document itself declares NIST quantum security level 0";
        }
        return switch (family) {
            case RSA -> "RSA integer factorisation";
            case ECC -> "elliptic-curve discrete logarithm";
            case DSA -> "finite-field discrete logarithm (DSA)";
            case FINITE_FIELD_DH -> "finite-field discrete logarithm (Diffie-Hellman/ElGamal)";
            case OTHER_ASYMMETRIC -> "a public-key algorithm the document itself declares NIST quantum security level 0";
        };
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

}
