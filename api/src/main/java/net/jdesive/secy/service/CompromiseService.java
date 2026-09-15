package net.jdesive.secy.service;

import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.compromise.CompromiseFilter;
import net.jdesive.secy.model.compromise.CompromiseFindingResponse;
import net.jdesive.secy.model.component.CorrelatableComponent;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Reads for the Compromise Findings screen, and the compromise half of {@code GET /actionable}.
 *
 * <p>{@code ActionableService} calls {@link #specification} and {@link #toResponse} rather than
 * building its own: the union's compromise arm and the dedicated {@code /compromise} endpoint must
 * select the same rows in the same order and describe them the same way, and the only way to
 * guarantee that is for there to be one implementation of each.
 */
@Service
@RequiredArgsConstructor
public class CompromiseService {

    /**
     * Sorts below every real {@code iocLastSeen}, so a finding whose feed stated no timestamp lands
     * at the bottom of its confidence band rather than the top of a descending sort — the same
     * problem, and the same coalesce fix, as {@code ActionableService.NO_EPSS}.
     */
    private static final LocalDateTime NO_IOC_TIMESTAMP = LocalDateTime.of(1970, 1, 1, 0, 0);

    private final CompromiseFindingRepository findingRepository;

    /** Paged findings for {@code GET /compromise}. */
    @Transactional(readOnly = true)
    public Page<CompromiseFindingResponse> find(int page, int size, CompromiseFilter filter) {
        return findingRepository.findAll(specification(filter), PageRequest.of(page, size))
                .map(CompromiseService::toResponse);
    }

    /** One finding in full, or empty when the id is unknown. */
    @Transactional(readOnly = true)
    public Optional<CompromiseFindingResponse> findDetail(UUID id) {
        return findingRepository.findById(id).map(CompromiseService::toResponse);
    }

    /* ------------------------------------------------------------------ */
    /* Query                                                              */
    /* ------------------------------------------------------------------ */

    /**
     * The one compromise-finding query, shared with {@code ActionableService}.
     *
     * <h2>The sort</h2>
     *
     * <p>Fixed, like {@code /actionable}'s, and for the same reason: "what should I look at first" is
     * the whole point of the screen. Severity is no help — every finding is {@code CRITICAL} by
     * construction — so the ranking is:
     *
     * <ol>
     *   <li><b>confidence</b>, {@code CONFIRMED} before {@code LIKELY} before {@code INVESTIGATE};</li>
     *   <li><b>{@code iocLastSeen} descending</b>, freshest indicator first, with findings whose feed
     *       stated no timestamp last rather than first;</li>
     *   <li>newest first, then id, so the order is total and a page boundary never duplicates or
     *       drops a row.</li>
     * </ol>
     *
     * <p>Confidence is ranked with a {@code CASE} expression rather than ordered on the column,
     * because {@code @Enumerated(STRING)} stores the enum name and a plain {@code ORDER BY} would
     * sort {@code CONFIRMED, INVESTIGATE, LIKELY} alphabetically — putting decayed evidence above
     * live evidence. Expressed in the specification (not as a stored rank column) so PostgreSQL and
     * the H2 the tests run against produce the identical order, which is the same trick
     * {@code ActionableService} uses for its {@code coalesce} on a null EPSS.
     */
    public static Specification<CompromiseFinding> specification(CompromiseFilter filter) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Non-negotiable: this screen shows what is still true. A finding a re-scan no longer
            // reproduces is kept as evidence but is not work — unless the caller asks for it.
            predicates.add(cb.equal(root.get("lifecycleState"), filter.effectiveLifecycleState()));

            if (filter.type() != null) {
                predicates.add(cb.equal(root.get("type"), filter.type()));
            }
            if (filter.confidence() != null) {
                predicates.add(cb.equal(root.get("confidence"), filter.confidence()));
            }
            if (filter.productId() != null) {
                Join<CompromiseFinding, SBOMComponent> component = root.join("component", JoinType.INNER);
                Join<SBOMComponent, SBOM> sbom = component.join("sbom", JoinType.INNER);
                predicates.add(cb.equal(sbom.get("product").get("id"), filter.productId()));
            }
            if (filter.assetId() != null) {
                Join<CompromiseFinding, AssetComponent> assetComponent =
                        root.join("assetComponent", JoinType.INNER);
                predicates.add(cb.equal(assetComponent.get("asset").get("id"), filter.assetId()));
            }
            if (filter.componentId() != null) {
                // Either kind — the caller holding a component id off an /actionable row should not
                // have to know which table it came from.
                predicates.add(cb.or(
                        cb.equal(root.get("component").get("id"), filter.componentId()),
                        cb.equal(root.get("assetComponent").get("id"), filter.componentId())));
            }

            // Spring Data only overwrites the ORDER BY when the Pageable carries a Sort, and callers
            // always pass an unsorted one; the count query must not get an ORDER BY at all.
            if (!isCountQuery(query.getResultType())) {
                query.orderBy(
                        cb.asc(confidenceRank(root, cb)),
                        cb.desc(cb.coalesce(root.<LocalDateTime>get("iocLastSeen"),
                                cb.literal(NO_IOC_TIMESTAMP))),
                        cb.desc(root.get("createdAt")),
                        cb.asc(root.get("id")));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    /** {@code CONFIRMED → 0, LIKELY → 1, everything else → 2}. See {@link #specification}. */
    private static Expression<Integer> confidenceRank(jakarta.persistence.criteria.Root<CompromiseFinding> root,
                                                      jakarta.persistence.criteria.CriteriaBuilder cb) {
        return cb.<Integer>selectCase()
                .when(cb.equal(root.get("confidence"), CompromiseConfidence.CONFIRMED), 0)
                .when(cb.equal(root.get("confidence"), CompromiseConfidence.LIKELY), 1)
                .otherwise(2)
                .as(Integer.class);
    }

    private static boolean isCountQuery(Class<?> resultType) {
        return Long.class.equals(resultType) || long.class.equals(resultType);
    }

    /* ------------------------------------------------------------------ */
    /* Mapping                                                            */
    /* ------------------------------------------------------------------ */

    /** One finding → its response, from whichever kind of component it cites. */
    public static CompromiseFindingResponse toResponse(CompromiseFinding finding) {
        CorrelatableComponent component = finding.getCorrelatableComponent();
        Product product = productOf(finding.getComponent());
        Asset asset = assetOf(finding.getAssetComponent());

        return new CompromiseFindingResponse(
                finding.getId(),
                finding.getType(),
                finding.getConfidence(),
                finding.getSeverity(),
                finding.getSource(),
                finding.getIocId(),
                finding.getMatchedOn(),
                finding.getSummary(),
                finding.getDetails(),
                finding.getOrigins(),
                finding.getReferencesJson(),
                finding.getIocFirstSeen(),
                finding.getIocLastSeen(),
                finding.getIocConfidence(),
                finding.getAgedAt(),
                finding.getLifecycleState(),
                product == null ? null : product.getId(),
                product == null ? null : product.getName(),
                asset == null ? null : asset.getId(),
                asset == null ? null : asset.getName(),
                componentIdOf(finding),
                component == null ? null : component.getName(),
                component == null ? null : component.getVersion(),
                component == null ? null : component.getPurl(),
                finding.getCreatedAt(),
                finding.getLastSeenAt());
    }

    /** The id of whichever component row the finding cites. */
    public static UUID componentIdOf(CompromiseFinding finding) {
        if (finding.getComponent() != null) {
            return finding.getComponent().getId();
        }
        return finding.getAssetComponent() == null ? null : finding.getAssetComponent().getId();
    }

    public static Product productOf(SBOMComponent component) {
        if (component == null || component.getSbom() == null) {
            return null;
        }
        return component.getSbom().getProduct();
    }

    public static Asset assetOf(AssetComponent component) {
        return component == null ? null : component.getAsset();
    }

}
