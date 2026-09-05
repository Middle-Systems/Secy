package net.jdesive.secy.job;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.JobType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Everything that writes an {@code ingestion_job} row.
 *
 * <p>The state transitions live here rather than in {@link JobRunner} for two reasons: they are all
 * short transactions (the runner's actual work is not, and must not hold one open), and calling
 * them from a different bean means Spring's proxy actually applies {@code @Transactional} — a
 * self-invocation inside the runner would silently run outside a transaction.
 *
 * <p>Concurrency: every transition re-reads the row inside its own transaction and writes through
 * the entity, so {@link Job#getVersion()} makes each write an optimistic-locking check. On top of
 * that, {@link #progress} and {@link #finish} refuse to touch a job that is already terminal, which
 * is what stops the reaper and a late-finishing worker from undoing each other.
 */
@Slf4j
@Service
public class JobService {

    /** The statuses that hold a type's single active slot. */
    private static final Set<JobStatus> ACTIVE = EnumSet.of(JobStatus.QUEUED, JobStatus.RUNNING);

    private static final int MESSAGE_MAX_LENGTH = 2048;

    private static final String SYSTEM = "system";

    private final JobRepository jobRepository;

    private final TransactionTemplate transactionTemplate;

    @Autowired
    public JobService(JobRepository jobRepository, TransactionTemplate transactionTemplate) {
        this.jobRepository = jobRepository;
        this.transactionTemplate = transactionTemplate;
    }

    /* ---------------------------------------------------------------------- */
    /* Public API                                                             */
    /* ---------------------------------------------------------------------- */

    /**
     * Queue an ingest of {@code type}, or return the one already queued/running.
     *
     * <p>Deliberately idempotent-ish: hammering the ingest button, or two operators clicking at
     * once, must not stack duplicate feed pulls. The check-then-insert covers the common case; the
     * partial unique index from migration {@code 003} covers the race, and losing that race is
     * handled by returning the winner.
     *
     * @param triggeredBy principal name, or null/blank for {@code "system"}
     */
    public Job enqueue(JobType type, String triggeredBy) {
        try {
            return transactionTemplate.execute(status -> createIfAbsent(type, triggeredBy));
        } catch (DataIntegrityViolationException e) {
            // uq_ingestion_job_active_type rejected the insert: a concurrent enqueue won. That
            // transaction has rolled back, so re-read outside it and hand back the winning job.
            log.debug("Concurrent enqueue for {} lost the unique-index race; returning the active job", type);
            return findActive(type).orElseThrow(() -> e);
        }
    }

    /** Convenience for controllers: derive {@code triggeredBy} from the request principal. */
    public Job enqueue(JobType type, Principal principal) {
        return enqueue(type, principal == null ? null : principal.getName());
    }

    /** A single job, or empty if the id is unknown. */
    @Transactional(readOnly = true)
    public Optional<Job> get(UUID id) {
        return jobRepository.findById(id);
    }

    /** Recent-first page of jobs, optionally narrowed by type and/or status. */
    @Transactional(readOnly = true)
    public Page<Job> list(int page, int size, JobType type, JobStatus status) {
        Pageable pageable = PageRequest.of(page, size);
        if (type != null && status != null) {
            return jobRepository.findByTypeAndStatusOrderByCreatedAtDesc(type, status, pageable);
        }
        if (type != null) {
            return jobRepository.findByTypeOrderByCreatedAtDesc(type, pageable);
        }
        if (status != null) {
            return jobRepository.findByStatusOrderByCreatedAtDesc(status, pageable);
        }
        return jobRepository.findAllByOrderByCreatedAtDesc(pageable);
    }

    /** The active job for a type, if one is queued or running. */
    @Transactional(readOnly = true)
    public Optional<Job> findActive(JobType type) {
        return jobRepository.findFirstByTypeAndStatusInOrderByCreatedAtAsc(type, ACTIVE);
    }

    /** Claim candidates for the poller, oldest first. */
    @Transactional(readOnly = true)
    public List<Job> findQueued() {
        return jobRepository.findByStatusOrderByCreatedAtAsc(JobStatus.QUEUED);
    }

    /* ---------------------------------------------------------------------- */
    /* Transitions — called by the runner and the reaper                      */
    /* ---------------------------------------------------------------------- */

    /**
     * Move a job {@code QUEUED -> RUNNING}, claiming it for this worker.
     *
     * @return the claimed job, or empty when someone else got there first
     */
    @Transactional
    public Optional<Job> claim(UUID id) {
        Job job = jobRepository.findById(id).orElse(null);
        if (job == null || job.getStatus() != JobStatus.QUEUED) {
            return Optional.empty();
        }
        job.setStatus(JobStatus.RUNNING);
        job.setStartedAt(LocalDateTime.now());
        job.setMessage("Starting…");
        try {
            // Flush inside the transaction so a lost version check surfaces here, not on commit.
            return Optional.of(jobRepository.saveAndFlush(job));
        } catch (OptimisticLockingFailureException e) {
            log.debug("Job {} was claimed concurrently", id);
            return Optional.empty();
        }
    }

    /** Record a running count. Ignored once the job is terminal — progress never resurrects. */
    @Transactional
    public void progress(UUID id, int itemsProcessed, String message) {
        Job job = jobRepository.findById(id).orElse(null);
        if (job == null || job.getStatus().isTerminal()) {
            return;
        }
        job.setItemsProcessed(itemsProcessed);
        job.setMessage(truncate(message));
        jobRepository.save(job);
    }

    /**
     * Move a job to a terminal status.
     *
     * <p>A job that is already terminal is left exactly as it is — if the reaper failed a stalled
     * run and the worker then came back to life, the reaper's verdict stands.
     */
    @Transactional
    public Optional<Job> finish(UUID id, JobStatus terminal, int itemsProcessed, String message) {
        if (!terminal.isTerminal()) {
            throw new IllegalArgumentException("Not a terminal status: " + terminal);
        }
        Job job = jobRepository.findById(id).orElse(null);
        if (job == null) {
            return Optional.empty();
        }
        if (job.getStatus().isTerminal()) {
            log.warn("Job {} already finished as {}; ignoring late {}", id, job.getStatus(), terminal);
            return Optional.of(job);
        }
        job.setStatus(terminal);
        job.setItemsProcessed(itemsProcessed);
        job.setMessage(truncate(message));
        job.setFinishedAt(LocalDateTime.now());
        return Optional.of(jobRepository.save(job));
    }

    /**
     * Fail every job that has been {@code RUNNING} longer than {@code staleTimeout} — the worker
     * that owned it died, or the whole app was killed mid-ingest.
     *
     * <p>The query only ever returns {@code RUNNING} rows, so this cannot touch a finished job. If
     * a worker commits its own result in between, the version check fails, this transaction rolls
     * back and the next tick sees the (now terminal) job and skips it.
     *
     * @return how many jobs were failed
     */
    @Transactional
    public int reapStale(java.time.Duration staleTimeout) {
        LocalDateTime cutoff = LocalDateTime.now().minus(staleTimeout);
        List<Job> stale = jobRepository.findByStatusAndStartedAtBefore(JobStatus.RUNNING, cutoff);
        if (stale.isEmpty()) {
            return 0;
        }
        for (Job job : stale) {
            log.warn("Reaping job {} ({}) — RUNNING since {} with no completion", job.getId(), job.getType(),
                    job.getStartedAt());
            job.setStatus(JobStatus.FAILED);
            job.setFinishedAt(LocalDateTime.now());
            job.setMessage(truncate("Timed out after " + staleTimeout + " with no completion; the worker is presumed dead."));
        }
        jobRepository.saveAll(stale);
        return stale.size();
    }

    /* ---------------------------------------------------------------------- */
    /* Internals                                                              */
    /* ---------------------------------------------------------------------- */

    private Job createIfAbsent(JobType type, String triggeredBy) {
        Optional<Job> active = jobRepository.findFirstByTypeAndStatusInOrderByCreatedAtAsc(type, ACTIVE);
        if (active.isPresent()) {
            log.debug("{} ingestion already {}; reusing job {}", type, active.get().getStatus(), active.get().getId());
            return active.get();
        }
        Job job = new Job();
        job.setType(type);
        job.setStatus(JobStatus.QUEUED);
        job.setCreatedAt(LocalDateTime.now());
        job.setItemsProcessed(0);
        job.setMessage("Queued");
        job.setTriggeredBy(triggeredBy == null || triggeredBy.isBlank() ? SYSTEM : triggeredBy);
        // saveAndFlush so the unique-index violation happens here, inside execute(), rather than at
        // commit time where the catch below could not see it.
        return jobRepository.saveAndFlush(job);
    }

    private static String truncate(String message) {
        if (message == null) {
            return null;
        }
        return message.length() <= MESSAGE_MAX_LENGTH ? message : message.substring(0, MESSAGE_MAX_LENGTH);
    }

}
