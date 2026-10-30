package net.jdesive.secy.service.vex;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.correlation.ComponentCoordinate;
import net.jdesive.secy.model.component.CorrelatableComponent;
import net.jdesive.secy.model.vex.VexExplanation;
import net.jdesive.secy.model.vex.VexStatementRole;
import net.jdesive.secy.persistence.VexPrecedenceConfigRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexPrecedenceConfig;
import net.jdesive.secy.persistence.entity.VexPrecedencePolicy;
import net.jdesive.secy.persistence.entity.VexStatement;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.scoring.RiskScoringService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Applies {@link VexResolver} to real alerts and statements — the only writer of
 * {@code VulnerabilityAlert.vexStatus}/{@code vexJustification}/{@code vexStatementId}/
 * {@code vexConflict}/{@code vexUpdatedAt} (see that entity's "VEX (M1f)" Javadoc section for why
 * {@code EnrichmentService} must never touch them).
 *
 * <p>Called from four places (design decision #1 — statements are stored independently of alerts and
 * matched wherever an alert's applicability could have changed): {@link #applyTo} from
 * {@code CorrelationService.reconcile} on every correlation run; {@link #reconcileCves} from
 * {@code VexIngestionService} after a document is ingested, superseded or deactivated;
 * {@link #reconcileAll} from {@link #setPolicy} after a precedence change; and directly from
 * {@code POST /vex/reconcile}.
 */
@Service
@RequiredArgsConstructor
public class VexResolutionService {

    private static final int CHUNK_SIZE = 500;

    private final VexStatementRepository vexStatementRepository;

    private final VexPrecedenceConfigRepository vexPrecedenceConfigRepository;

    private final VulnerabilityAlertRepository alertRepository;

    /** M1i: rescores an alert whose VEX snapshot just changed — see {@link #writeResolution}. */
    private final RiskScoringService riskScoringService;

    /** A summary of one reconciliation pass — how many alerts were looked at, and how many changed. */
    public record VexReconcileSummary(int alertsEvaluated, int alertsChanged) {
    }

    /** The tenant's configured precedence policy, or {@link VexPrecedenceConfig#DEFAULT_POLICY} if unconfigured. */
    @Transactional(readOnly = true)
    public VexPrecedencePolicy getPolicy(UUID tenantId) {
        return vexPrecedenceConfigRepository.findByTenantId(tenantId)
                .map(VexPrecedenceConfig::getPolicy)
                .orElse(VexPrecedenceConfig.DEFAULT_POLICY);
    }

    /**
     * Resolves VEX for a batch of alerts <b>without saving them</b> — the caller (correlation) is
     * about to save them anyway as part of a larger batch.
     *
     * <p><b>Fast path:</b> when a tenant has no active VEX statements at all (true for every tenant
     * before its first upload), this only touches alerts that already carry a stale snapshot —
     * normally none — so behaviour and query counts are identical to before M1f for the common case.
     */
    @Transactional
    public void applyTo(Collection<VulnerabilityAlert> alerts) {
        if (alerts == null || alerts.isEmpty()) {
            return;
        }
        Map<UUID, List<VulnerabilityAlert>> byTenant = alerts.stream()
                .collect(Collectors.groupingBy(a -> a.getTenantId() == null ? Tenant.DEFAULT_TENANT_ID : a.getTenantId()));

        for (Map.Entry<UUID, List<VulnerabilityAlert>> entry : byTenant.entrySet()) {
            UUID tenantId = entry.getKey();
            List<VulnerabilityAlert> tenantAlerts = entry.getValue();

            if (!vexStatementRepository.existsByTenantIdAndActiveTrue(tenantId)) {
                for (VulnerabilityAlert alert : tenantAlerts) {
                    if (alert.getVexStatus() != null || alert.isVexConflict() || alert.getVexStatementId() != null) {
                        writeResolution(alert, VexResolver.VexResolution.NONE);
                    }
                }
                continue;
            }

            VexPrecedencePolicy policy = getPolicy(tenantId);
            Set<String> cveIds = tenantAlerts.stream()
                    .map(a -> a.getVulnerability() == null ? null : a.getVulnerability().getId())
                    .filter(Objects::nonNull)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            Map<String, List<VexStatement>> statementsByCve = loadActiveStatements(tenantId, cveIds);

            for (VulnerabilityAlert alert : tenantAlerts) {
                VexResolver.AlertTarget target = targetOf(alert);
                if (target == null) {
                    continue;
                }
                List<VexStatement> candidates = statementsByCve.getOrDefault(target.cveId(), List.of());
                VexResolver.VexResolution resolution = candidates.isEmpty()
                        ? VexResolver.VexResolution.NONE
                        : VexResolver.resolve(target, candidates, policy);
                writeResolution(alert, resolution);
            }
        }
    }

    /** Re-resolves and saves (only the changed ones of) every alert for one tenant's CVEs. */
    @Transactional
    public VexReconcileSummary reconcileCves(UUID tenantId, Set<String> cveIds) {
        if (cveIds == null || cveIds.isEmpty()) {
            return new VexReconcileSummary(0, 0);
        }
        List<VulnerabilityAlert> alerts = new ArrayList<>();
        List<String> chunkBuffer = new ArrayList<>(cveIds);
        for (int i = 0; i < chunkBuffer.size(); i += CHUNK_SIZE) {
            List<String> chunk = chunkBuffer.subList(i, Math.min(i + CHUNK_SIZE, chunkBuffer.size()));
            alerts.addAll(alertRepository.findAllForVexReconcile(tenantId, chunk));
        }

        VexPrecedencePolicy policy = getPolicy(tenantId);
        Map<String, List<VexStatement>> statementsByCve = loadActiveStatements(tenantId, cveIds);

        List<VulnerabilityAlert> changed = new ArrayList<>();
        for (VulnerabilityAlert alert : alerts) {
            VexResolver.AlertTarget target = targetOf(alert);
            if (target == null) {
                continue;
            }
            List<VexStatement> candidates = statementsByCve.getOrDefault(target.cveId(), List.of());
            VexResolver.VexResolution resolution = candidates.isEmpty()
                    ? VexResolver.VexResolution.NONE
                    : VexResolver.resolve(target, candidates, policy);
            if (writeResolution(alert, resolution)) {
                changed.add(alert);
            }
        }
        if (!changed.isEmpty()) {
            alertRepository.saveAll(changed);
        }
        return new VexReconcileSummary(alerts.size(), changed.size());
    }

    /**
     * Re-resolves every CVE with either an active statement or a (possibly now-stale) VEX snapshot on
     * some alert — picks up both "a new statement might now apply" and "a statement was deactivated
     * and an alert's snapshot needs clearing".
     */
    @Transactional
    public VexReconcileSummary reconcileAll(UUID tenantId) {
        Set<String> cveIds = new LinkedHashSet<>(vexStatementRepository.findDistinctActiveCveIds(tenantId));
        cveIds.addAll(alertRepository.findDistinctVexAnnotatedCveIds(tenantId));
        return reconcileCves(tenantId, cveIds);
    }

    /**
     * Upserts the tenant's precedence policy, then synchronously re-resolves everything it could
     * affect.
     *
     * <p><b>Deviation from the M1f plan's literal signature</b> (which specced a bare
     * {@code VexPrecedencePolicy} return): returns the {@link VexReconcileSummary} from the
     * synchronous reconcile pass this method already has to run, so {@code VexController} can report
     * real "N alerts evaluated / M changed" numbers on {@code PUT /vex/settings/precedence} without a
     * second, redundant reconcile call whose counts would misleadingly read as zero (everything would
     * already be resolved by the first pass).
     */
    @Transactional
    public VexReconcileSummary setPolicy(UUID tenantId, VexPrecedencePolicy policy) {
        VexPrecedenceConfig config = vexPrecedenceConfigRepository.findByTenantId(tenantId).orElseGet(() -> {
            VexPrecedenceConfig fresh = new VexPrecedenceConfig();
            fresh.setTenantId(tenantId);
            return fresh;
        });
        config.setPolicy(policy);
        vexPrecedenceConfigRepository.save(config);
        // Synchronous for now -- Javadoc note: this could become a job if the tenant's alert volume
        // ever makes a policy flip expensive enough to matter.
        return reconcileAll(tenantId);
    }

    /** Every statement applicable to one alert, with its resolution role, for the detail endpoint. */
    @Transactional(readOnly = true)
    public VexExplanation explain(VulnerabilityAlert alert) {
        UUID tenantId = alert.getTenantId() == null ? Tenant.DEFAULT_TENANT_ID : alert.getTenantId();
        VexPrecedencePolicy policy = getPolicy(tenantId);
        VexResolver.AlertTarget target = targetOf(alert);
        if (target == null) {
            return new VexExplanation(policy, List.of());
        }
        List<VexStatement> candidates = vexStatementRepository
                .findAllByTenantIdAndActiveTrueAndCveIdIn(tenantId, List.of(target.cveId()));
        if (candidates.isEmpty()) {
            return new VexExplanation(policy, List.of());
        }
        VexResolver.VexResolution resolution = VexResolver.resolve(target, candidates, policy);
        Map<UUID, VexStatement> byId = candidates.stream().collect(Collectors.toMap(VexStatement::getId, s -> s));

        Comparator<VexExplanation.Applied> order = Comparator
                .comparing((VexExplanation.Applied a) -> rolePriority(a.role()))
                .thenComparing(a -> a.statement().getStatementTimestamp(), Comparator.nullsLast(Comparator.reverseOrder()));

        List<VexExplanation.Applied> applied = resolution.roles().entrySet().stream()
                .map(e -> new VexExplanation.Applied(byId.get(e.getKey()), e.getValue()))
                .filter(a -> a.statement() != null)
                .sorted(order)
                .toList();

        return new VexExplanation(policy, applied);
    }

    /* ------------------------------------------------------------------ */
    /* Internals                                                          */
    /* ------------------------------------------------------------------ */

    private static int rolePriority(VexStatementRole role) {
        return switch (role) {
            case WON -> 0;
            case AGREES -> 1;
            case CONFLICTING -> 2;
            case OVERRIDDEN -> 3;
            case SUPERSEDED -> 4;
        };
    }

    private Map<String, List<VexStatement>> loadActiveStatements(UUID tenantId, Collection<String> cveIds) {
        Map<String, List<VexStatement>> byCve = new HashMap<>();
        List<String> buffer = new ArrayList<>(cveIds);
        for (int i = 0; i < buffer.size(); i += CHUNK_SIZE) {
            List<String> chunk = buffer.subList(i, Math.min(i + CHUNK_SIZE, buffer.size()));
            for (VexStatement statement : vexStatementRepository.findAllByTenantIdAndActiveTrueAndCveIdIn(tenantId, chunk)) {
                byCve.computeIfAbsent(statement.getCveId(), k -> new ArrayList<>()).add(statement);
            }
        }
        return byCve;
    }

    /** Builds the resolver's input from a real alert, or null when the alert has no component or no CVE yet. */
    private VexResolver.AlertTarget targetOf(VulnerabilityAlert alert) {
        CorrelatableComponent component = alert.getCorrelatableComponent();
        if (component == null || alert.getVulnerability() == null || alert.getVulnerability().getId() == null) {
            return null;
        }
        String identityKey = component.getIdentityKey();
        if (identityKey == null) {
            return null;
        }
        String version = ComponentCoordinate.of(component).version();
        UUID productId = null;
        if (alert.getComponent() != null && alert.getComponent().getSbom() != null) {
            Product product = alert.getComponent().getSbom().getProduct();
            productId = product == null ? null : product.getId();
        }
        return new VexResolver.AlertTarget(alert.getVulnerability().getId(), identityKey, version, productId);
    }

    /**
     * Writes the four snapshot fields; bumps {@code vexUpdatedAt} only when something actually
     * changed. M1i: also rescores the alert when it changed, so {@code riskScore} picks up the new
     * VEX multiplier (e.g. a fresh {@code NOT_AFFECTED} zeroing it) without waiting for the next
     * enrichment pass — never when nothing changed, which keeps the fast path (no active statements)
     * exactly as query-free as it was before M1i.
     */
    private boolean writeResolution(VulnerabilityAlert alert, VexResolver.VexResolution resolution) {
        VexStatus newStatus = resolution.status();
        VexJustification newJustification = resolution.justification();
        UUID newStatementId = resolution.winningStatementId();
        boolean newConflict = resolution.conflict();

        boolean changed = !Objects.equals(alert.getVexStatus(), newStatus)
                || !Objects.equals(alert.getVexJustification(), newJustification)
                || !Objects.equals(alert.getVexStatementId(), newStatementId)
                || alert.isVexConflict() != newConflict;

        alert.setVexStatus(newStatus);
        alert.setVexJustification(newJustification);
        alert.setVexStatementId(newStatementId);
        alert.setVexConflict(newConflict);
        if (changed) {
            alert.setVexUpdatedAt(LocalDateTime.now());
            riskScoringService.apply(alert);
        }
        return changed;
    }

}
