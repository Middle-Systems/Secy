--liquibase formatted sql

-- Phase 7 — Triage workflow (ROADMAP.md).
--
-- What a PERSON decided, orthogonal to lifecycle_state (what the SCANNER last observed) —
-- see AlertLifecycleState's Javadoc, which has said since Phase 2 that this phase should add its own
-- column rather than extend that one. So: triage_state + snoozed_until + assignee_id added to both
-- vulnerability_alert and compromise_finding (the same two columns, the same defaults, because the
-- typed union at the API edge needs both arms to carry the same triage shape), plus a new
-- triage_event table for the append-only history — one row per state transition and/or comment.
--
-- triage_event's parent reference is the same two-nullable-FK-with-XOR pattern as
-- vulnerability_alert.component/asset_component (009) and compromise_finding.component/
-- asset_component (011d): one event is about exactly one of a VulnerabilityAlert or a
-- CompromiseFinding, never both and never neither.

--changeset secy:014a-triage-columns
alter table vulnerability_alert add column triage_state varchar(16) not null default 'OPEN';
alter table vulnerability_alert add column snoozed_until timestamp(6);
alter table vulnerability_alert add column assignee_id uuid;

alter table vulnerability_alert add constraint fk_vuln_alert_assignee
    foreign key (assignee_id) references app_user (id);

create index idx_vuln_alert_triage_state on vulnerability_alert (triage_state);

alter table compromise_finding add column triage_state varchar(16) not null default 'OPEN';
alter table compromise_finding add column snoozed_until timestamp(6);
alter table compromise_finding add column assignee_id uuid;

alter table compromise_finding add constraint fk_compromise_finding_assignee
    foreign key (assignee_id) references app_user (id);

create index idx_compromise_finding_triage_state on compromise_finding (triage_state);

--rollback drop index if exists idx_compromise_finding_triage_state;
--rollback alter table compromise_finding drop constraint if exists fk_compromise_finding_assignee;
--rollback alter table compromise_finding drop column assignee_id;
--rollback alter table compromise_finding drop column snoozed_until;
--rollback alter table compromise_finding drop column triage_state;
--rollback drop index if exists idx_vuln_alert_triage_state;
--rollback alter table vulnerability_alert drop constraint if exists fk_vuln_alert_assignee;
--rollback alter table vulnerability_alert drop column assignee_id;
--rollback alter table vulnerability_alert drop column snoozed_until;
--rollback alter table vulnerability_alert drop column triage_state;

--changeset secy:014b-triage-event
create table triage_event (
    id                      uuid          not null,
    vulnerability_alert_id  uuid,
    compromise_finding_id   uuid,
    from_state              varchar(16),
    to_state                varchar(16),
    comment                 varchar(4096),
    changed_by_id           uuid          not null,
    created_at              timestamp(6)  not null,
    constraint pk_triage_event primary key (id),
    constraint fk_triage_event_vuln_alert
        foreign key (vulnerability_alert_id) references vulnerability_alert (id) on delete cascade,
    constraint fk_triage_event_compromise_finding
        foreign key (compromise_finding_id) references compromise_finding (id) on delete cascade,
    constraint fk_triage_event_changed_by
        foreign key (changed_by_id) references app_user (id)
);

-- The XOR: one event describes exactly one parent, the same discipline
-- ck_vuln_alert_one_component (009) and ck_compromise_finding_one_component (011d) enforce.
alter table triage_event
    add constraint ck_triage_event_one_parent
    check (num_nonnulls(vulnerability_alert_id, compromise_finding_id) = 1);

create index idx_triage_event_vuln_alert on triage_event (vulnerability_alert_id);
create index idx_triage_event_compromise_finding on triage_event (compromise_finding_id);

--rollback drop table if exists triage_event;
