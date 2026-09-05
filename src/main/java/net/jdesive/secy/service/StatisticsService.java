package net.jdesive.secy.service;

import net.jdesive.secy.model.DashboardStats;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class StatisticsService {
    
    @Autowired
    private VulnerabilityRepository cveRepo;

    @Autowired
    private KEVRepository kevRepo;

    @Autowired
    private EPSSRepository epssRepo;

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

        return stats;
    }
}