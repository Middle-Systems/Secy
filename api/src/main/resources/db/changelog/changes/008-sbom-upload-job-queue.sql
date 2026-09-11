--liquibase formatted sql

-- Phase 3 — SBOM upload goes through the job queue (ROADMAP.md, "SBOM breadth + ingest
-- hardening"), consistent with the feed ingests. Two independent schema changes:
--
--   (a) sbom.pending_raw_body / sbom.job_id -- the ingestion_job table has no generic payload
--       column (deliberately: every other job type is a stateless singleton feed pull with
--       nothing to parametrize), so per-invocation data for a SBOM_UPLOAD job lives on the
--       domain row instead. SBOMController parses and validates the upload synchronously (a
--       document that can never succeed is still rejected with 400 before anything is queued),
--       then persists a placeholder `sbom` row holding the raw JSON body and pointing at the job
--       it just enqueued. SbomIngestJobService looks the row up by job_id, re-parses
--       pending_raw_body (parsing is a pure, cheap function of the bytes -- re-running it inside
--       the job is simpler and safer than serializing NormalizedSbom's record tree through a
--       column of its own), persists the real components, and clears pending_raw_body once
--       consumed.
--
--   (b) uq_ingestion_job_active_type (from 003) enforces one active job per *type*, which is
--       right for a singleton feed pull but wrong for SBOM_UPLOAD: two products (or two uploads
--       to the same product) uploading concurrently must each get their own job, not collapse
--       onto one. JobService.create() (as opposed to enqueue()) skips the dedup check in Java for
--       this type; this narrows the index so the database does not reject the concurrent inserts
--       either.

--changeset secy:008a-sbom-upload-job-payload
alter table sbom add column pending_raw_body text;
alter table sbom add column job_id uuid;

create index idx_sbom_job_id on sbom (job_id);

--rollback drop index if exists idx_sbom_job_id;
--rollback alter table sbom drop column job_id;
--rollback alter table sbom drop column pending_raw_body;

--changeset secy:008b-ingestion-job-per-invocation-types
drop index uq_ingestion_job_active_type;

create unique index uq_ingestion_job_active_type
    on ingestion_job (type)
    where status in ('QUEUED', 'RUNNING') and type <> 'SBOM_UPLOAD';

--rollback drop index if exists uq_ingestion_job_active_type;
--rollback create unique index uq_ingestion_job_active_type on ingestion_job (type) where status in ('QUEUED', 'RUNNING');
