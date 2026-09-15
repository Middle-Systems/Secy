package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.config.CompromiseProperties;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

/**
 * IOC aging: the nightly sweep that stops stale evidence from shouting forever.
 *
 * <h2>The problem it solves</h2>
 *
 * <p>A compromise finding is {@code CRITICAL} by construction and sorts above everything else on the
 * primary screen. That is right the week a malicious package lands in your build. It is not right
 * three years later, for a registry-pulled package nobody has re-observed since, still holding the
 * top slot ahead of a live KEV. An indicator has a shelf life, and the finding's position on the
 * screen should reflect it.
 *
 * <h2>Demote, never delete</h2>
 *
 * <p>A decayed finding moves {@code CONFIRMED}/{@code LIKELY} → {@link CompromiseConfidence#INVESTIGATE}
 * and stays exactly where it is. Phase 2's rule holds here too: the history is evidence, and a
 * deleted row silently loses whatever triage a human had done to it. {@code INVESTIGATE} is the
 * honest label — "this was real, we cannot currently corroborate it, go and look".
 *
 * <h2>One staleness rule, two callers</h2>
 *
 * <p>{@link #applyAging(CompromiseFinding, LocalDateTime)} is the rule, and
 * {@code CompromiseDetectionService} calls it on every finding it writes. Without that, the two
 * would fight: detection re-derives confidence from the feed evidence on every SBOM upload and would
 * cheerfully restore {@code CONFIRMED} on a finding this job had just demoted, so a stale IOC would
 * flip back and forth depending on which ran last. Routing both through one method means a freshly
 * re-ingested IOC is re-promoted (because its {@code iocLastSeen} moved, which is exactly what
 * should re-promote it) and a stale one is not (because it did not).
 *
 * <h2>Why a plain {@code @Scheduled} and not a {@link net.jdesive.secy.persistence.entity.Job}</h2>
 *
 * <p>The job queue exists for work that is long, externally-dependent, cancellable and worth showing
 * a progress bar for. This is a single bounded {@code UPDATE} over rows the database can select
 * directly; a job row would add a queue round-trip and a UI entry for something with no observable
 * duration. The timer lives on {@code JobScheduler} with the other two, so every {@code @Scheduled}
 * in the application is in one place and tests can drive this method directly.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CompromiseAgingService {

    /** The two confidences aging can demote. {@code INVESTIGATE} is already the floor. */
    private static final Set<CompromiseConfidence> DEMOTABLE =
            Set.of(CompromiseConfidence.CONFIRMED, CompromiseConfidence.LIKELY);

    private final CompromiseFindingRepository findingRepository;

    private final CompromiseProperties properties;

    /**
     * Demote every active finding whose IOC has decayed past
     * {@code secy.compromise.ioc-stale-after}.
     *
     * <p>Idempotent: a second run the same night finds nothing, because the rows it demoted are now
     * at {@code INVESTIGATE} and the query only selects {@link #DEMOTABLE} ones.
     *
     * @return how many findings were demoted
     */
    @Transactional
    public int ageFindings() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime staleBefore = staleBefore(now);
        if (staleBefore == null) {
            return 0;
        }

        List<CompromiseFinding> stale = findingRepository.findStale(
                AlertLifecycleState.ACTIVE, DEMOTABLE, staleBefore);
        if (stale.isEmpty()) {
            return 0;
        }

        for (CompromiseFinding finding : stale) {
            finding.setConfidence(CompromiseConfidence.INVESTIGATE);
            finding.setAgedAt(now);
        }
        findingRepository.saveAll(stale);

        log.info("IOC aging demoted {} compromise finding(s) to INVESTIGATE (stale before {})",
                stale.size(), staleBefore);
        return stale.size();
    }

    /**
     * Apply the same staleness rule to a single finding, in memory, before it is persisted.
     *
     * <p>Called by {@code CompromiseDetectionService} on every finding it creates or refreshes, so
     * detection and the nightly sweep can never disagree about whether an indicator is current. It
     * only ever demotes — a finding whose evidence says {@code LIKELY} is not promoted here just
     * because the IOC is fresh.
     *
     * @param finding the finding, with its confidence and IOC timestamps already set
     * @param now     the clock to measure against, passed in so a whole detection pass shares one
     */
    public void applyAging(CompromiseFinding finding, LocalDateTime now) {
        LocalDateTime staleBefore = staleBefore(now);
        if (staleBefore == null || !DEMOTABLE.contains(finding.getConfidence())) {
            return;
        }
        LocalDateTime reference = finding.freshnessReference();
        if (reference != null && reference.isBefore(staleBefore)) {
            finding.setConfidence(CompromiseConfidence.INVESTIGATE);
            finding.setAgedAt(now);
        }
    }

    /**
     * The cut-off, or null when aging is switched off or misconfigured.
     *
     * <p>A zero or negative {@code ioc-stale-after} disables aging rather than demoting everything
     * instantly: an operator who typoed a duration should get the pre-Phase-6 behaviour, not a
     * dashboard where every compromise finding has silently dropped to {@code INVESTIGATE}.
     */
    private LocalDateTime staleBefore(LocalDateTime now) {
        if (!properties.isAgingEnabled()) {
            return null;
        }
        Duration staleAfter = properties.getIocStaleAfter();
        if (staleAfter == null || staleAfter.isZero() || staleAfter.isNegative()) {
            return null;
        }
        return now.minus(staleAfter);
    }

}
