package net.jdesive.secy.service.finding;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.component.CorrelatableComponent;
import net.jdesive.secy.model.finding.FindingRef;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.QuantumVulnerabilityFindingRepository;
import net.jdesive.secy.persistence.SbomQualityFindingRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityFinding;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomQualityFinding;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.CompromiseService;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Resolves a {@link FindingType}/id pair against whichever of the five finding tables it names,
 * returning an immutable {@link ResolvedFinding} snapshot. The generalized form of
 * {@code TriageService.Target}'s "switch, don't share an interface" choice — see that class's Javadoc
 * — widened from two tables to five (plus {@link FindingType#PROVENANCE}'s stub, which never
 * resolves). {@code TriageService} itself is unchanged and still serves only the two triageable types.
 *
 * <p>Callers run inside {@code @Transactional(readOnly = true)} ({@link FindingService}), so the
 * lazy {@code component.sbom.product} / {@code assetComponent.asset} walk for
 * {@code VULNERABILITY}/{@code COMPROMISE} rows is safe.
 */
@Component
@RequiredArgsConstructor
public class FindingResolver {

    /** Same cut as {@code ActionableService.SUMMARY_LENGTH} — a CVE description is trimmed identically here. */
    private static final int SUMMARY_LENGTH = 280;

    private final VulnerabilityAlertRepository alertRepository;
    private final CompromiseFindingRepository compromiseRepository;
    private final LifecycleDriftFindingRepository driftRepository;
    private final QuantumVulnerabilityFindingRepository quantumRepository;
    private final SbomQualityFindingRepository qualityRepository;
    private final ProductRepository productRepository;

    @Transactional(readOnly = true)
    public Optional<ResolvedFinding> resolve(FindingType type, UUID id) {
        if (type == null || id == null) {
            return Optional.empty();
        }
        return switch (type) {
            case VULNERABILITY -> alertRepository.findById(id).map(FindingResolver::from);
            case COMPROMISE -> compromiseRepository.findById(id).map(FindingResolver::from);
            case LIFECYCLE_DRIFT -> driftRepository.findById(id)
                    .map(f -> from(f, productName(f.getProductId())));
            case QUANTUM_VULNERABLE -> quantumRepository.findById(id)
                    .map(f -> from(f, productName(f.getProductId())));
            case SBOM_QUALITY -> qualityRepository.findById(id)
                    .map(f -> from(f, productName(f.getProductId())));
            case PROVENANCE -> Optional.empty();
        };
    }

    /** Batch resolution, one {@code findAllById} per distinct type present in {@code refs}. */
    @Transactional(readOnly = true)
    public Map<FindingRef, ResolvedFinding> resolveAll(Collection<FindingRef> refs) {
        Map<FindingRef, ResolvedFinding> result = new LinkedHashMap<>();
        if (refs == null || refs.isEmpty()) {
            return result;
        }

        Map<FindingType, List<UUID>> idsByType = new EnumMap<>(FindingType.class);
        for (FindingRef ref : refs) {
            if (ref == null || ref.type() == null || ref.id() == null || !ref.type().backedByTable()) {
                continue;
            }
            idsByType.computeIfAbsent(ref.type(), t -> new ArrayList<>()).add(ref.id());
        }

        // Batch the product-name lookup for the three plain-productId types once, rather than once
        // per row.
        Set<UUID> productIds = new HashSet<>();
        List<LifecycleDriftFinding> driftFindings = idsByType.containsKey(FindingType.LIFECYCLE_DRIFT)
                ? driftRepository.findAllById(idsByType.get(FindingType.LIFECYCLE_DRIFT))
                : List.of();
        driftFindings.forEach(f -> productIds.add(f.getProductId()));
        List<QuantumVulnerabilityFinding> quantumFindings = idsByType.containsKey(FindingType.QUANTUM_VULNERABLE)
                ? quantumRepository.findAllById(idsByType.get(FindingType.QUANTUM_VULNERABLE))
                : List.of();
        quantumFindings.forEach(f -> productIds.add(f.getProductId()));
        List<SbomQualityFinding> qualityFindings = idsByType.containsKey(FindingType.SBOM_QUALITY)
                ? qualityRepository.findAllById(idsByType.get(FindingType.SBOM_QUALITY))
                : List.of();
        qualityFindings.forEach(f -> productIds.add(f.getProductId()));

        Map<UUID, String> productNames = new HashMap<>();
        if (!productIds.isEmpty()) {
            productRepository.findAllById(productIds).forEach(p -> productNames.put(p.getId(), p.getName()));
        }

        if (idsByType.containsKey(FindingType.VULNERABILITY)) {
            alertRepository.findAllById(idsByType.get(FindingType.VULNERABILITY))
                    .forEach(a -> result.put(new FindingRef(FindingType.VULNERABILITY, a.getId()), from(a)));
        }
        if (idsByType.containsKey(FindingType.COMPROMISE)) {
            compromiseRepository.findAllById(idsByType.get(FindingType.COMPROMISE))
                    .forEach(f -> result.put(new FindingRef(FindingType.COMPROMISE, f.getId()), from(f)));
        }
        driftFindings.forEach(f -> result.put(new FindingRef(FindingType.LIFECYCLE_DRIFT, f.getId()),
                from(f, productNames.get(f.getProductId()))));
        quantumFindings.forEach(f -> result.put(new FindingRef(FindingType.QUANTUM_VULNERABLE, f.getId()),
                from(f, productNames.get(f.getProductId()))));
        qualityFindings.forEach(f -> result.put(new FindingRef(FindingType.SBOM_QUALITY, f.getId()),
                from(f, productNames.get(f.getProductId()))));

        return result;
    }

    private String productName(UUID productId) {
        if (productId == null) {
            return null;
        }
        return productRepository.findById(productId).map(Product::getName).orElse(null);
    }

    /* ------------------------------------------------------------------ */
    /* Per-entity mappers                                                 */
    /* ------------------------------------------------------------------ */

    static ResolvedFinding from(VulnerabilityAlert alert) {
        Vulnerability cve = alert.getVulnerability();
        CorrelatableComponent component = alert.getCorrelatableComponent();
        Product product = productOf(alert.getComponent());
        Asset asset = assetOf(alert.getAssetComponent());

        return new ResolvedFinding(
                FindingType.VULNERABILITY,
                alert.getId(),
                alert.getTenantId(),
                cve == null ? null : cve.getId(),
                cve == null ? null : summarize(cve.getDescription()),
                cve == null ? null : cve.getBaseSeverity(),
                product == null ? null : product.getId(),
                product == null ? null : product.getName(),
                asset == null ? null : asset.getId(),
                asset == null ? null : asset.getName(),
                component == null ? null : component.getName(),
                component == null ? null : component.getVersion(),
                component == null ? null : component.getPurl(),
                alert.getLifecycleState(),
                alert.getCreatedAt(),
                alert.getLastSeenAt(),
                alert.getRiskScore(),
                alert.getVexStatus(),
                alert.getVexJustification(),
                alert.isVexConflict(),
                alert.getTriageState(),
                alert.getSnoozedUntil());
    }

    static ResolvedFinding from(CompromiseFinding finding) {
        CorrelatableComponent component = finding.getCorrelatableComponent();
        Product product = CompromiseService.productOf(finding.getComponent());
        Asset asset = CompromiseService.assetOf(finding.getAssetComponent());

        return new ResolvedFinding(
                FindingType.COMPROMISE,
                finding.getId(),
                finding.getTenantId(),
                finding.getIocId(),
                finding.getSummary(),
                finding.getSeverity(),
                product == null ? null : product.getId(),
                product == null ? null : product.getName(),
                asset == null ? null : asset.getId(),
                asset == null ? null : asset.getName(),
                component == null ? null : component.getName(),
                component == null ? null : component.getVersion(),
                component == null ? null : component.getPurl(),
                finding.getLifecycleState(),
                finding.getCreatedAt(),
                finding.getLastSeenAt(),
                null,
                null, null, false,
                finding.getTriageState(),
                finding.getSnoozedUntil());
    }

    static ResolvedFinding from(LifecycleDriftFinding f, String productName) {
        return new ResolvedFinding(
                FindingType.LIFECYCLE_DRIFT,
                f.getId(),
                f.getTenantId(),
                f.getStagePair() + " " + f.getDriftKind(),
                f.getSummary(),
                null,
                f.getProductId(),
                productName,
                null, null,
                f.getComponentName(),
                f.getObservedVersion(),
                f.getComponentPurl(),
                f.getLifecycleState(),
                f.getCreatedAt(),
                f.getLastSeenAt(),
                null, null, null, false, null, null);
    }

    static ResolvedFinding from(QuantumVulnerabilityFinding f, String productName) {
        return new ResolvedFinding(
                FindingType.QUANTUM_VULNERABLE,
                f.getId(),
                f.getTenantId(),
                String.valueOf(f.getAlgorithmFamily()),
                f.getSummary(),
                null,
                f.getProductId(),
                productName,
                null, null,
                f.getComponentName(),
                null, null,
                f.getLifecycleState(),
                f.getCreatedAt(),
                f.getLastSeenAt(),
                null, null, null, false, null, null);
    }

    static ResolvedFinding from(SbomQualityFinding f, String productName) {
        Integer score = f.getQuality() == null ? null : f.getQuality().getScore();
        return new ResolvedFinding(
                FindingType.SBOM_QUALITY,
                f.getId(),
                f.getTenantId(),
                "SBOM quality " + score,
                f.getSummary(),
                null,
                f.getProductId(),
                productName,
                null, null,
                null, null, null,
                f.getLifecycleState(),
                f.getCreatedAt(),
                f.getLastSeenAt(),
                null, null, null, false, null, null);
    }

    private static Product productOf(SBOMComponent component) {
        if (component == null || component.getSbom() == null) {
            return null;
        }
        return component.getSbom().getProduct();
    }

    private static Asset assetOf(AssetComponent component) {
        return component == null ? null : component.getAsset();
    }

    private static String summarize(String description) {
        if (description == null || description.length() <= SUMMARY_LENGTH) {
            return description;
        }
        return description.substring(0, SUMMARY_LENGTH) + "…";
    }

}
