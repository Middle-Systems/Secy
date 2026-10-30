--liquibase formatted sql

-- M1i -- Scoring engine rework. See ROADMAP.md's "M1i -- Scoring engine rework". Every
-- vulnerability_alert carries a denormalized 0-100 risk score (risk_score) computed by
-- RiskScoringService from its own CVSS/KEV/EPSS/exploit-maturity/fix/VEX snapshots plus its
-- component's SBOM lifecycle stage, and the weights model version that produced it. Written on
-- enrichment, on VEX resolution change, and by the RISK_RESCORE job -- orthogonal to actionable /
-- triage_state. Dependency depth is a neutral placeholder until M1l. No backfill in SQL (weights live
-- in Java): pre-M1i rows stay NULL until the next re-enrichment or a POST /risk-score/rescore.
-- Asset/product rollups are computed on read, not stored.

--changeset secy:027a-vulnerability-alert-risk-score
--comment denormalized per-finding risk score snapshot, its weights model version and when it last changed
alter table vulnerability_alert add column risk_score float8;
alter table vulnerability_alert add column risk_score_model varchar(32);
alter table vulnerability_alert add column risk_scored_at timestamp(6);
alter table vulnerability_alert add constraint ck_vulnerability_alert_risk_score_range
    check (risk_score is null or (risk_score >= 0 and risk_score <= 100));
create index idx_vuln_alert_actionable_risk_score
    on vulnerability_alert (risk_score desc nulls last)
    where actionable;
--rollback drop index if exists idx_vuln_alert_actionable_risk_score;
--rollback alter table vulnerability_alert drop constraint if exists ck_vulnerability_alert_risk_score_range;
--rollback alter table vulnerability_alert drop column risk_scored_at;
--rollback alter table vulnerability_alert drop column risk_score_model;
--rollback alter table vulnerability_alert drop column risk_score;
