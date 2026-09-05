package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.JobType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface JobRepository extends JpaRepository<Job, UUID> {

    /** The job currently holding the "one active job per type" slot, if any. */
    Optional<Job> findFirstByTypeAndStatusInOrderByCreatedAtAsc(JobType type, Collection<JobStatus> statuses);

    /** Claim candidates, oldest first — the poller drains this in FIFO order. */
    List<Job> findByStatusOrderByCreatedAtAsc(JobStatus status);

    /**
     * Reaper scan. Filtering on {@code status} in the query is what keeps the reaper from ever
     * touching — let alone resurrecting — a job that has already reached a terminal state.
     */
    List<Job> findByStatusAndStartedAtBefore(JobStatus status, LocalDateTime cutoff);

    /* Recent-first listings for GET /jobs, with the optional type/status filters. */

    Page<Job> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<Job> findByTypeOrderByCreatedAtDesc(JobType type, Pageable pageable);

    Page<Job> findByStatusOrderByCreatedAtDesc(JobStatus status, Pageable pageable);

    Page<Job> findByTypeAndStatusOrderByCreatedAtDesc(JobType type, JobStatus status, Pageable pageable);

}
