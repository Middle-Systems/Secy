package net.jdesive.secy.service.lifecycle;

import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.lifecycle.LifecycleDriftFilter;
import net.jdesive.secy.model.lifecycle.LifecycleDriftFindingResponse;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Reads for {@code GET /lifecycle-drift}. Same shape as {@code CompromiseService}'s query half. */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class LifecycleDriftQueryService {

    private final LifecycleDriftFindingRepository findingRepository;

    public Page<LifecycleDriftFindingResponse> find(int page, int size, LifecycleDriftFilter filter) {
        return findingRepository.findAll(specification(filter), PageRequest.of(page, size))
                .map(LifecycleDriftFindingResponse::from);
    }

    public Optional<LifecycleDriftFindingResponse> findDetail(UUID id) {
        return findingRepository.findById(id).map(LifecycleDriftFindingResponse::from);
    }

    /**
     * Sort: newest first, then id, so a page boundary is total and never duplicates/drops a row —
     * same guard {@code CompromiseService.specification} uses for the count-query {@code ORDER BY}.
     */
    private static Specification<LifecycleDriftFinding> specification(LifecycleDriftFilter filter) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(cb.equal(root.get("lifecycleState"), filter.effectiveLifecycleState()));

            if (filter.productId() != null) {
                predicates.add(cb.equal(root.get("productId"), filter.productId()));
            }
            if (filter.stagePair() != null) {
                predicates.add(cb.equal(root.get("stagePair"), filter.stagePair()));
            }
            if (filter.driftKind() != null) {
                predicates.add(cb.equal(root.get("driftKind"), filter.driftKind()));
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
