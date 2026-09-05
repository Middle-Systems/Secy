--liquibase formatted sql

-- Asynchronous ingestion job queue. POST /nvd/ingest, /epss/ingest and /kev/ingest no longer run
-- the feed pull on the request thread: they insert a row here and hand back 202 + the job id, and a
-- scheduled poller claims the row and runs it on a bounded worker pool.

--changeset secy:003-ingestion-queue
--comment Background ingestion job queue for the NVD / EPSS / KEV feed pulls

create table ingestion_job (
    id uuid not null,
    type varchar(16) not null,
    status varchar(16) not null,
    created_at timestamp(6) not null,
    started_at timestamp(6),
    finished_at timestamp(6),
    items_processed integer not null default 0,
    message varchar(2048),
    triggered_by varchar(255),
    version bigint not null default 0,
    primary key (id)
);

-- GET /jobs lists recent-first.
create index idx_ingestion_job_created_at on ingestion_job (created_at desc);

-- Drives the poller's QUEUED scan and the reaper's RUNNING scan.
create index idx_ingestion_job_status on ingestion_job (status);

-- Backstop for the "one active job per feed type" rule. JobService checks for an active job before
-- inserting, but two concurrent enqueues can both pass that check; this partial unique index makes
-- the loser's insert fail, and JobService returns the winning job instead.
create unique index uq_ingestion_job_active_type
    on ingestion_job (type)
    where status in ('QUEUED', 'RUNNING');

--rollback drop index if exists uq_ingestion_job_active_type;
--rollback drop index if exists idx_ingestion_job_status;
--rollback drop index if exists idx_ingestion_job_created_at;
--rollback drop table if exists ingestion_job;
