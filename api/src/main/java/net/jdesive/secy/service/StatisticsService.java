package net.jdesive.secy.service;

import net.jdesive.secy.model.DashboardStats;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class StatisticsService {

    @Autowired
    private VulnerabilityRepository cveRepo;

    @Autowired
    private KEVRepository kevRepo;

    @Autowired
    private EPSSRepository epssRepo;

    @Autowired
    private VulnerabilityAlertRepository alertRepo;

    public DashboardStats getDashboardMetrics() {
        LocalDateTime sevenDaysAgo = LocalDateTime.now().minusDays(7);

        DashboardStats stats = new DashboardStats();

        // 1. Global Syncs (NVD + KEV + EPSS updates)
        stats.setGlobalSyncs(
                cveRepo.countByLastModifiedAfter(sevenDaysAgo) +
                        kevRepo.countByAddedAfter(sevenDaysAgo) +
                        epssRepo.countByDateAfter(sevenDaysAgo)
        );

        // 2. Active Exploits (CISA KEV Total)
        stats.setActiveKevCount(kevRepo.count());

        // 3. High Probability EPSS (Updated in last 7d with score > 0.36)
        stats.setHighEpssCount(epssRepo.countHighProbabilityRecent(0.36, sevenDaysAgo));

        // 4. Accessible Threats (AV:N / AC:L)
        stats.setAccessibleCount(cveRepo.countAccessibleThreats());

        // 5. Severity Distribution for Doughnut Chart
        stats.setGlobalCrit(cveRepo.countByBaseSeverity("CRITICAL"));
        stats.setGlobalHigh(cveRepo.countByBaseSeverity("HIGH"));
        stats.setGlobalMed(cveRepo.countByBaseSeverity("MEDIUM"));
        stats.setGlobalLow(cveRepo.countByBaseSeverity("LOW"));

        // 6. The funnel's output — what the operator is actually expected to work through.
        applyActionableMetrics(stats, sevenDaysAgo);

        return stats;
    }

    /**
     * Roll-ups over {@code vulnerability_alert}, all restricted to {@code actionable = true}.
     *
     * <p>Reads the denormalized enrichment columns rather than re-deriving the funnel, so these
     * numbers agree with {@code GET /actionable} by construction.
     */
    private void applyActionableMetrics(DashboardStats stats, LocalDateTime sevenDaysAgo) {
        stats.setOpenActionableCount(alertRepo.countByActionableTrue());

        // Deliberately overlapping: KEV_AND_EPSS_HIGH belongs to both tiles.
        stats.setActionableKevCount(alertRepo.countByActionableTrueAndActionableReasonIn(
                List.of(ActionableReason.KEV, ActionableReason.KEV_AND_EPSS_HIGH)));
        stats.setActionableEpssCount(alertRepo.countByActionableTrueAndActionableReasonIn(
                List.of(ActionableReason.EPSS_HIGH, ActionableReason.KEV_AND_EPSS_HIGH)));

        stats.setActionableCrit(alertRepo.countActionableBySeverity("CRITICAL"));
        stats.setActionableHigh(alertRepo.countActionableBySeverity("HIGH"));
        stats.setActionableMed(alertRepo.countActionableBySeverity("MEDIUM"));
        stats.setActionableLow(alertRepo.countActionableBySeverity("LOW"));

        stats.setActionableWithFixCount(alertRepo.countByActionableTrueAndFixState(FixState.FIXED));
        stats.setActionableNoFixCount(alertRepo.countByActionableTrueAndFixStateIn(
                List.of(FixState.NO_FIX, FixState.UNKNOWN)));

        stats.setActionableExploitNone(alertRepo.countByActionableTrueAndExploitMaturity(ExploitMaturity.NONE));
        stats.setActionableExploitPoc(alertRepo.countByActionableTrueAndExploitMaturity(ExploitMaturity.POC));
        stats.setActionableExploitWeaponized(
                alertRepo.countByActionableTrueAndExploitMaturity(ExploitMaturity.WEAPONIZED));
        stats.setActionableExploitInTheWild(
                alertRepo.countByActionableTrueAndExploitMaturity(ExploitMaturity.IN_THE_WILD));

        stats.setPastKevDueCount(alertRepo.countActionablePastKevDue(LocalDate.now()));
        stats.setActionableCreatedLast7d(alertRepo.countByActionableTrueAndCreatedAtAfter(sevenDaysAgo));
    }
}
