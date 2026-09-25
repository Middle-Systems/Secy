package net.jdesive.secy.service.cbom;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.cbom.CryptoAssetDetailResponse;
import net.jdesive.secy.model.cbom.CryptoAssetFilter;
import net.jdesive.secy.model.cbom.CryptoAssetResponse;
import net.jdesive.secy.model.cbom.QuantumFindingFilter;
import net.jdesive.secy.model.cbom.QuantumFindingResponse;
import net.jdesive.secy.persistence.QuantumVulnerabilityFindingRepository;
import net.jdesive.secy.persistence.SBOMComponentCryptoAssetRepository;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityFinding;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SBOMComponentCryptoAsset;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Reads for {@code GET /cbom/**} (M1g). Same shape as {@code LifecycleDriftQueryService}. */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CbomQueryService {

    private final SBOMComponentCryptoAssetRepository cryptoAssetRepository;
    private final QuantumVulnerabilityFindingRepository findingRepository;
    private final ObjectMapper objectMapper;

    /* ------------------------------------------------------------------ */
    /* Assets                                                              */
    /* ------------------------------------------------------------------ */

    public Page<CryptoAssetResponse> findAssets(int page, int size, CryptoAssetFilter filter) {
        return cryptoAssetRepository.findAll(assetSpecification(filter), PageRequest.of(page, size))
                .map(CryptoAssetResponse::from);
    }

    public Optional<CryptoAssetResponse> findAssetDetail(UUID id) {
        return cryptoAssetRepository.findById(id).map(CryptoAssetResponse::from);
    }

    public Optional<CryptoAssetDetailResponse> findAssetDetailFull(UUID id) {
        return cryptoAssetRepository.findById(id).map(entity -> CryptoAssetDetailResponse.from(entity, objectMapper));
    }

    /** Sorted by component name asc then id asc, default {@code sbom.active = true} only. */
    private static Specification<SBOMComponentCryptoAsset> assetSpecification(CryptoAssetFilter filter) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            Join<SBOMComponentCryptoAsset, SBOMComponent> component = root.join("component", JoinType.INNER);
            Join<SBOMComponent, SBOM> sbom = component.join("sbom", JoinType.INNER);

            if (!filter.includeInactive()) {
                predicates.add(cb.isTrue(sbom.get("active")));
            }
            if (filter.productId() != null) {
                predicates.add(cb.equal(sbom.get("product").get("id"), filter.productId()));
            }
            if (filter.sbomId() != null) {
                predicates.add(cb.equal(sbom.get("id"), filter.sbomId()));
            }
            if (filter.assetType() != null) {
                predicates.add(cb.equal(root.get("assetType"), filter.assetType()));
            }
            if (filter.quantumStatus() != null) {
                predicates.add(cb.equal(root.get("quantumStatus"), filter.quantumStatus()));
            }

            if (!isCountQuery(query.getResultType())) {
                query.orderBy(cb.asc(component.get("name")), cb.asc(root.get("id")));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    /* ------------------------------------------------------------------ */
    /* Quantum findings                                                    */
    /* ------------------------------------------------------------------ */

    public Page<QuantumFindingResponse> findFindings(int page, int size, QuantumFindingFilter filter) {
        return findingRepository.findAll(findingSpecification(filter), PageRequest.of(page, size))
                .map(QuantumFindingResponse::from);
    }

    public Optional<QuantumFindingResponse> findFindingDetail(UUID id) {
        return findingRepository.findById(id).map(QuantumFindingResponse::from);
    }

    /** Sorted newest first, then id — a page boundary is total and never duplicates/drops a row. */
    private static Specification<QuantumVulnerabilityFinding> findingSpecification(QuantumFindingFilter filter) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(cb.equal(root.get("lifecycleState"), filter.effectiveLifecycleState()));

            if (filter.productId() != null) {
                predicates.add(cb.equal(root.get("productId"), filter.productId()));
            }
            if (filter.assetType() != null) {
                predicates.add(cb.equal(root.get("assetType"), filter.assetType()));
            }
            if (filter.family() != null) {
                predicates.add(cb.equal(root.get("algorithmFamily"), filter.family()));
            }

            if (!isCountQuery(query.getResultType())) {
                query.orderBy(cb.desc(root.get("createdAt")), cb.asc(root.get("id")));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    private static boolean isCountQuery(Class<?> resultType) {
        return Long.class.equals(resultType) || long.class.equals(resultType);
    }

}
