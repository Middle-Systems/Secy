package net.jdesive.secy.service.scoring;

import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * The seam for per-tenant scoring weights. Every tenant gets {@link ScoringWeights#DEFAULT} today —
 * future expansion — do not add config here in M1. A later milestone can materialise a per-tenant
 * row into a {@link ScoringWeights} here without any caller of {@link #forTenant} changing.
 */
@Component
public class ScoringWeightsProvider {

    public ScoringWeights forTenant(UUID tenantId) {
        return ScoringWeights.DEFAULT;
    }

}
