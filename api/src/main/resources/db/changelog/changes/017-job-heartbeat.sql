--liquibase formatted sql

-- The reaper judged staleness by total RUNNING duration, which fails a job whose legitimate
-- runtime exceeds stale-timeout -- exactly what a first-time NVD backward-bootstrap sweep does,
-- rate-limited to one request per few seconds across 25+ years of windows. Track a heartbeat
-- instead: reap only when nothing has been reported in stale-timeout, not when the job has simply
-- been running that long. See JobService.progress/claim/reapStale.

--changeset secy:017-job-heartbeat
--comment last_progress_at is the reaper's actual staleness signal; started_at is kept for display

alter table ingestion_job add column last_progress_at timestamp(6);
update ingestion_job set last_progress_at = coalesce(started_at, created_at);

--rollback alter table ingestion_job drop column last_progress_at;
