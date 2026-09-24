--liquibase formatted sql

-- The bootstrap sweep's own frontier, tracked separately from nvd_ingest_cursor.last_modified (015)
-- now that bootstrap walks backward from "now" toward the epoch (newest, most actionable data
-- first) instead of forward from the epoch -- see NvdIngestCursor's class Javadoc for why.

--changeset secy:016-nvd-bootstrap-frontier
--comment the backward bootstrap sweep's own progress marker, separate from the forward high-water mark

alter table nvd_ingest_cursor add column oldest_swept_modified_date timestamp(6);

--rollback alter table nvd_ingest_cursor drop column oldest_swept_modified_date;
