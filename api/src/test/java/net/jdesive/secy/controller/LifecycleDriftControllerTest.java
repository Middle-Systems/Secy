package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
import net.jdesive.secy.persistence.entity.LifecycleDriftKind;
import net.jdesive.secy.persistence.entity.LifecycleStagePair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /lifecycle-drift} and {@code GET /lifecycle-drift/{id}} (M1e). Findings are seeded
 * directly via the repository — the diff engine itself is {@code LifecycleDiffServiceTest}'s and
 * {@code LifecycleDriftAcceptanceTest}'s job.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
@Transactional
class LifecycleDriftControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private LifecycleDriftFindingRepository findingRepository;

    private UUID productId;
    private UUID activeId;
    private UUID autoResolvedId;

    @BeforeEach
    void seed() {
        findingRepository.deleteAll();

        productId = UUID.randomUUID();

        activeId = seedFinding(productId, LifecycleStagePair.SOURCE_BUILD, LifecycleDriftKind.UNEXPECTED_COMPONENT,
                "npm/acme-internal-utils", AlertLifecycleState.ACTIVE);
        autoResolvedId = seedFinding(productId, LifecycleStagePair.BUILD_DEPLOYED, LifecycleDriftKind.VERSION_MISMATCH,
                "npm/lodash", AlertLifecycleState.AUTO_RESOLVED);
    }

    @Test
    void defaultListReturnsOnlyActive() throws Exception {
        mockMvc.perform(get("/lifecycle-drift").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(activeId.toString()))
                .andExpect(jsonPath("$.content[0].lifecycleState").value("ACTIVE"))
                .andExpect(jsonPath("$.content[0].stagePair").value("SOURCE_BUILD"))
                .andExpect(jsonPath("$.content[0].category").value("DEPENDENCY_CONFUSION_OR_BUILD_INJECTION"))
                .andExpect(jsonPath("$.content[0].baselineStage").value("SOURCE"))
                .andExpect(jsonPath("$.content[0].observedStage").value("BUILD"))
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    void lifecycleStateFilterShowsAutoResolved() throws Exception {
        mockMvc.perform(get("/lifecycle-drift")
                        .param("productId", productId.toString())
                        .param("lifecycleState", "AUTO_RESOLVED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(autoResolvedId.toString()));
    }

    @Test
    void stagePairAndDriftKindFiltersNarrowTheResult() throws Exception {
        mockMvc.perform(get("/lifecycle-drift")
                        .param("productId", productId.toString())
                        .param("lifecycleState", "AUTO_RESOLVED")
                        .param("stagePair", "BUILD_DEPLOYED")
                        .param("driftKind", "VERSION_MISMATCH"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(autoResolvedId.toString()));

        mockMvc.perform(get("/lifecycle-drift")
                        .param("productId", productId.toString())
                        .param("lifecycleState", "AUTO_RESOLVED")
                        .param("stagePair", "SOURCE_BUILD"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(0));
    }

    @Test
    void detailReturns200ForAKnownId() throws Exception {
        mockMvc.perform(get("/lifecycle-drift/{id}", activeId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(activeId.toString()))
                .andExpect(jsonPath("$.identityKey").value("npm/acme-internal-utils"));
    }

    @Test
    void detailReturns404ForAnUnknownId() throws Exception {
        mockMvc.perform(get("/lifecycle-drift/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    private UUID seedFinding(UUID productId, LifecycleStagePair pair, LifecycleDriftKind kind, String identityKey,
                             AlertLifecycleState state) {
        LifecycleDriftFinding finding = new LifecycleDriftFinding();
        finding.setProductId(productId);
        finding.setStagePair(pair);
        finding.setDriftKind(kind);
        finding.setIdentityKey(identityKey);
        finding.setComponentName(identityKey.substring(identityKey.indexOf('/') + 1));
        finding.setBaselineSbomId(UUID.randomUUID());
        finding.setObservedSbomId(UUID.randomUUID());
        finding.setSummary("Seeded by LifecycleDriftControllerTest.");
        finding.setLifecycleState(state);
        finding.setLastSeenAt(LocalDateTime.now());
        return findingRepository.saveAndFlush(finding).getId();
    }

}
