package net.jdesive.secy.model;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
public class DashboardStats {
    private long globalSyncs;      // CVEs + KEVs + EPSS updated in last 7d
    private long activeKevCount;   // Total size of KEV table
    private long highEpssCount;    // EPSS > 0.36 updated in last 7d
    private long accessibleCount;  // AV:N and AC:L in global CVE table

    private long globalCrit;
    private long globalHigh;
    private long globalMed;
    private long globalLow;
}
