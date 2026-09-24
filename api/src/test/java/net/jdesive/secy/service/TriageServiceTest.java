package net.jdesive.secy.service;

import net.jdesive.secy.model.actionable.TriageEventResponse;
import net.jdesive.secy.model.actionable.TriageStatusResponse;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.TriageEventRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code TriageService}: the Phase 7 state machine that resolves across the typed union
 * ({@code VulnerabilityAlert} / {@code CompromiseFinding}), records every change as a new
 * {@link TriageEvent}, and never fails a bulk update over one bad id.
 *
 * <p>{@code @Transactional} — the H2 database is shared across every {@code @SpringBootTest} context
 * in the run; without a per-test rollback this class's fixtures would leak into whatever test class
 * runs next.
 */
@SpringBootTest
@Transactional
class TriageServiceTest {

    @Autowired
    private TriageService triageService;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private TriageEventRepository eventRepository;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    private User analyst;
    private User otherAnalyst;
    private UUID alertId;
    private UUID findingId;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run — clear anything a
        // TriageEvent could hold a FK into before clearing the rows it points at.
        eventRepository.deleteAll();
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        userRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();

        analyst = user("analyst@example.com", "Alex Analyst");
        otherAnalyst = user("second@example.com", "Sam Second");

        Product product = new Product();
        product.setName("Acme Web");
        productRepository.save(product);

        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        component.setType("library");

        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        component.setSbom(sbom);
        sbom.getComponents().add(component);
        sbomRepository.save(sbom);

        Vulnerability cve = new Vulnerability();
        cve.setId("CVE-2099-9001");
        cve.setDescription("Seeded by TriageServiceTest");
        cve.setBaseSeverity("CRITICAL");
        cve.setCvssScore(9.8d);
        // save() on an entity with an assigned (non-generated) id merges rather than persists, and
        // merge() returns a NEW managed instance — the original reference stays transient. Reassign,
        // or VulnerabilityAlert.vulnerability ends up pointing at an unsaved transient instance.
        cve = cveRepository.save(cve);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.KEV);
        alertId = alertRepository.save(alert).getId();

        CompromiseFinding finding = new CompromiseFinding();
        finding.setComponent(component);
        finding.setType(CompromiseType.MALICIOUS_PACKAGE);
        finding.setConfidence(CompromiseConfidence.CONFIRMED);
        finding.setSource("OpenSSF Malicious Packages");
        finding.setIocId("MAL-2099-0001");
        finding.setMatchedOn("pkg:npm/evil-pkg@1.0.0");
        finding.setSummary("Malicious code in evil-pkg (npm)");
        findingId = findingRepository.save(finding).getId();
    }

    /* ------------------------------------------------------------------ */
    /* updateState — vulnerability arm                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void updateStateMovesAVulnerabilityAlertAndRecordsTheTransition() {
        Optional<TriageStatusResponse> result = triageService.updateState(
                alertId, TriageState.ACKNOWLEDGED, null, null, "Looking into it", analyst);

        assertThat(result).isPresent();
        TriageStatusResponse status = result.get();
        assertThat(status.id()).isEqualTo(alertId);
        assertThat(status.triageState()).isEqualTo(TriageState.ACKNOWLEDGED);

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.getTriageState()).isEqualTo(TriageState.ACKNOWLEDGED);

        List<TriageEvent> events = eventRepository.findAllByVulnerabilityAlertIdOrderByCreatedAtAsc(alertId);
        assertThat(events).hasSize(1);
        TriageEvent event = events.get(0);
        assertThat(event.getFromState()).isEqualTo(TriageState.OPEN);
        assertThat(event.getToState()).isEqualTo(TriageState.ACKNOWLEDGED);
        assertThat(event.getComment()).isEqualTo("Looking into it");
        assertThat(event.getChangedBy().getId()).isEqualTo(analyst.getId());
    }

    @Test
    void updateStateSetsAssigneeAndSnoozeWithoutTouchingStateWhenStateIsNull() {
        LocalDateTime snoozeUntil = LocalDateTime.now().plusDays(3);

        Optional<TriageStatusResponse> result = triageService.updateState(
                alertId, null, otherAnalyst.getId(), snoozeUntil, null, analyst);

        assertThat(result).isPresent();
        assertThat(result.get().triageState()).isEqualTo(TriageState.OPEN);
        assertThat(result.get().assigneeId()).isEqualTo(otherAnalyst.getId());
        assertThat(result.get().snoozedUntil()).isEqualTo(snoozeUntil);

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.getTriageState()).isEqualTo(TriageState.OPEN);
        assertThat(reloaded.getAssignee().getId()).isEqualTo(otherAnalyst.getId());
        assertThat(reloaded.getSnoozedUntil()).isEqualTo(snoozeUntil);
    }

    /* ------------------------------------------------------------------ */
    /* updateState — compromise arm                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void updateStateMovesACompromiseFindingAndRecordsTheTransition() {
        Optional<TriageStatusResponse> result = triageService.updateState(
                findingId, TriageState.FALSE_POSITIVE, null, null, "Not actually deployed", analyst);

        assertThat(result).isPresent();
        assertThat(result.get().triageState()).isEqualTo(TriageState.FALSE_POSITIVE);

        CompromiseFinding reloaded = findingRepository.findById(findingId).orElseThrow();
        assertThat(reloaded.getTriageState()).isEqualTo(TriageState.FALSE_POSITIVE);

        List<TriageEvent> events = eventRepository.findAllByCompromiseFindingIdOrderByCreatedAtAsc(findingId);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getFromState()).isEqualTo(TriageState.OPEN);
        assertThat(events.get(0).getToState()).isEqualTo(TriageState.FALSE_POSITIVE);
        assertThat(events.get(0).getComment()).isEqualTo("Not actually deployed");
    }

    /* ------------------------------------------------------------------ */
    /* History accumulates rather than overwrites                         */
    /* ------------------------------------------------------------------ */

    @Test
    void repeatedCallsAccumulateHistoryInChronologicalOrder() {
        triageService.updateState(alertId, TriageState.ACKNOWLEDGED, null, null, "first", analyst);
        triageService.updateState(alertId, TriageState.SNOOZED, null, LocalDateTime.now().plusDays(1), "second", analyst);
        triageService.addComment(alertId, "just a note", otherAnalyst);
        triageService.updateState(alertId, TriageState.RESOLVED, null, null, null, analyst);

        Optional<List<TriageEventResponse>> history = triageService.history(alertId);
        assertThat(history).isPresent();
        List<TriageEventResponse> events = history.get();
        assertThat(events).hasSize(4);

        // Oldest first.
        assertThat(events.get(0).toState()).isEqualTo(TriageState.ACKNOWLEDGED);
        assertThat(events.get(1).toState()).isEqualTo(TriageState.SNOOZED);
        assertThat(events.get(2).fromState()).isNull();
        assertThat(events.get(2).toState()).isNull();
        assertThat(events.get(2).comment()).isEqualTo("just a note");
        assertThat(events.get(3).toState()).isEqualTo(TriageState.RESOLVED);

        // Each event stands on its own — nothing was overwritten.
        assertThat(events).extracting(TriageEventResponse::id).doesNotHaveDuplicates();

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.getTriageState()).isEqualTo(TriageState.RESOLVED);
    }

    /* ------------------------------------------------------------------ */
    /* addComment                                                         */
    /* ------------------------------------------------------------------ */

    @Test
    void addCommentRecordsANullTransitionAndLeavesStateUntouched() {
        Optional<TriageEventResponse> result = triageService.addComment(findingId, "Confirmed via manual review", analyst);

        assertThat(result).isPresent();
        TriageEventResponse event = result.get();
        assertThat(event.fromState()).isNull();
        assertThat(event.toState()).isNull();
        assertThat(event.comment()).isEqualTo("Confirmed via manual review");
        assertThat(event.changedById()).isEqualTo(analyst.getId());

        CompromiseFinding reloaded = findingRepository.findById(findingId).orElseThrow();
        assertThat(reloaded.getTriageState()).isEqualTo(TriageState.OPEN);
    }

    /* ------------------------------------------------------------------ */
    /* bulkUpdateState                                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void bulkUpdateStateAppliesToBothArmsAndSkipsUnresolvableIdsWithoutFailing() {
        UUID unknownId = UUID.randomUUID();

        int updated = triageService.bulkUpdateState(
                List.of(alertId, findingId, unknownId), TriageState.ACKNOWLEDGED, otherAnalyst.getId(), analyst);

        assertThat(updated).isEqualTo(2);

        VulnerabilityAlert reloadedAlert = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloadedAlert.getTriageState()).isEqualTo(TriageState.ACKNOWLEDGED);
        assertThat(reloadedAlert.getAssignee().getId()).isEqualTo(otherAnalyst.getId());

        CompromiseFinding reloadedFinding = findingRepository.findById(findingId).orElseThrow();
        assertThat(reloadedFinding.getTriageState()).isEqualTo(TriageState.ACKNOWLEDGED);
        assertThat(reloadedFinding.getAssignee().getId()).isEqualTo(otherAnalyst.getId());

        assertThat(eventRepository.findAllByVulnerabilityAlertIdOrderByCreatedAtAsc(alertId)).hasSize(1);
        assertThat(eventRepository.findAllByCompromiseFindingIdOrderByCreatedAtAsc(findingId)).hasSize(1);
    }

    /* ------------------------------------------------------------------ */
    /* Resolution failure                                                 */
    /* ------------------------------------------------------------------ */

    @Test
    void anIdThatResolvesToNeitherTableComesBackEmptyEverywhere() {
        UUID unknownId = UUID.randomUUID();

        assertThat(triageService.updateState(unknownId, TriageState.ACKNOWLEDGED, null, null, null, analyst)).isEmpty();
        assertThat(triageService.addComment(unknownId, "no-op", analyst)).isEmpty();
        assertThat(triageService.history(unknownId)).isEmpty();
    }

    /* ------------------------------------------------------------------ */
    /* Seeding helpers                                                    */
    /* ------------------------------------------------------------------ */

    private User user(String email, String displayName) {
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash("{noop}not-a-real-hash");
        user.setDisplayName(displayName);
        user.setRole(Role.USER);
        user.setEnabled(true);
        return userRepository.save(user);
    }

}
