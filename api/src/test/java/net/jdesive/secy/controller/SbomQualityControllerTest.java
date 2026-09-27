package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.SbomQualityFindingRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.SbomQualityFinding;
import net.jdesive.secy.persistence.entity.SbomQualityScore;
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
 * {@code GET /sbom-quality} and {@code GET /sbom-quality/{id}} (M1h). Findings are seeded directly
 * via the repository — the scorer/reconciler itself is {@code SbomQualityScorerTest}'s,
 * {@code SbomQualityFindingServiceTest}'s and {@code SbomQualityAcceptanceTest}'s job.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
@Transactional
class SbomQualityControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SbomQualityFindingRepository findingRepository;

    private UUID productId;
    private UUID activeUnstagedId;
    private UUID activeBuildId;
    private UUID autoResolvedId;

    @BeforeEach
    void seed() {
        findingRepository.deleteAll();

        productId = UUID.randomUUID();

        activeUnstagedId = seedFinding(productId, null, 33, AlertLifecycleState.ACTIVE);
        activeBuildId = seedFinding(productId, SbomLifecycleStage.BUILD, 57, AlertLifecycleState.ACTIVE);
        autoResolvedId = seedFinding(productId, SbomLifecycleStage.DEPLOYED, 40, AlertLifecycleState.AUTO_RESOLVED);
    }

    @Test
    void defaultListReturnsOnlyActive() throws Exception {
        mockMvc.perform(get("/sbom-quality").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(2))
                .andExpect(jsonPath("$.totalElements").value(2));
    }

    @Test
    void lifecycleStateFilterShowsAutoResolved() throws Exception {
        mockMvc.perform(get("/sbom-quality")
                        .param("productId", productId.toString())
                        .param("lifecycleState", "AUTO_RESOLVED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(autoResolvedId.toString()));
    }

    @Test
    void lifecycleStageFilterNarrowsToTheBuildSlot() throws Exception {
        mockMvc.perform(get("/sbom-quality")
                        .param("productId", productId.toString())
                        .param("lifecycleStage", "BUILD"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(activeBuildId.toString()))
                .andExpect(jsonPath("$.content[0].quality.score").value(57))
                .andExpect(jsonPath("$.content[0].scoreThreshold").value(70));
    }

    @Test
    void unstagedSlotHasANullLifecycleStage() throws Exception {
        mockMvc.perform(get("/sbom-quality/{id}", activeUnstagedId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(activeUnstagedId.toString()))
                .andExpect(jsonPath("$.lifecycleStage").doesNotExist())
                .andExpect(jsonPath("$.quality.score").value(33));
    }

    @Test
    void detailReturns404ForAnUnknownId() throws Exception {
        mockMvc.perform(get("/sbom-quality/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    private UUID seedFinding(UUID productId, SbomLifecycleStage stage, int score, AlertLifecycleState state) {
        SbomQualityScore quality = new SbomQualityScore();
        quality.setScore(score);
        quality.setSupplierCoverage(0);
        quality.setNameCoverage(100);
        quality.setVersionCoverage(100);
        quality.setUniqueIdCoverage(33);
        quality.setDependencyCoverage(0);
        quality.setHasAuthor(false);
        quality.setHasTimestamp(false);
        quality.setComponentsScored(3);

        SbomQualityFinding finding = new SbomQualityFinding();
        finding.setProductId(productId);
        finding.setLifecycleStage(stage);
        finding.setSbomId(UUID.randomUUID());
        finding.setQuality(quality);
        finding.setScoreThreshold(70);
        finding.setMissingElements("SUPPLIER,UNIQUE_IDENTIFIER,DEPENDENCY_RELATIONSHIP,AUTHOR,TIMESTAMP");
        finding.setSummary("Seeded by SbomQualityControllerTest.");
        finding.setLifecycleState(state);
        finding.setLastSeenAt(LocalDateTime.now());
        return findingRepository.saveAndFlush(finding).getId();
    }

}
