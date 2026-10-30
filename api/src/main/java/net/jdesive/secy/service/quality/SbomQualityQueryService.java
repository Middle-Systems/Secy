package net.jdesive.secy.service.quality;

import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.quality.SbomQualityFindingFilter;
import net.jdesive.secy.model.quality.SbomQualityFindingResponse;
import net.jdesive.secy.persistence.SbomQualityFindingRepository;
import net.jdesive.secy.persistence.entity.SbomQualityFinding;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Reads for {@code GET /sbom-quality}. Same shape as {@code LifecycleDriftQueryService}. */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class SbomQualityQueryService {

    private final SbomQualityFindingRepository findingRepository;

    public Page<SbomQualityFindingResponse> find(int page, int size, SbomQualityFindingFilter filter) {
        return findingRepository.findAll(specification(filter), PageRequest.of(page, size))
                .map(SbomQualityFindingResponse::from);
    }

    public Optional<SbomQualityFindingResponse> findDetail(UUID id) {
        return findingRepository.findById(id).map(SbomQualityFindingResponse::from);
    }

    /**
     * Sort: newest first, then id, so a page boundary is total and never duplicates/drops a row —
     * same guard {@code LifecycleDriftQueryService.specification} uses for the count-query
     * {@code ORDER BY}.
     */
    private static Specification<SbomQualityFinding> specification(SbomQualityFindingFilter filter) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(cb.equal(root.get("lifecycleState"), filter.effectiveLifecycleState()));

            if (filter.productId() != null) {
                predicates.add(cb.equal(root.get("productId"), filter.productId()));
            }
            if (filter.sbomId() != null) {
                predicates.add(cb.equal(root.get("sbomId"), filter.sbomId()));
            }
            if (filter.lifecycleStage() != null) {
                predicates.add(cb.equal(root.get("lifecycleStage"), filter.lifecycleStage()));
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
