--liquibase formatted sql

-- M1j -- Finding & Action-item model. See ROADMAP.md's "M1j -- Finding & Action-item model".
-- "Finding" is a read-model over the five existing finding tables (vulnerability_alert,
-- compromise_finding, lifecycle_drift_finding, quantum_vulnerability_finding, sbom_quality_finding),
-- none of which change here. action_item is the concrete remediation task, scoped to exactly one
-- product or asset; action_item_finding links it to its findings (one typed nullable column per
-- finding table, exactly one set -- the triage_event 014b XOR pattern generalized to five; one
-- action item per finding); action_item_event is its append-only history. NOT_AFFECTED is derived
-- from the VEX snapshot and never stored; auto-reopen and risk-acceptance expiry are derived on
-- read. Risk acceptance records acceptor/expiry/justification and an optional approver -- no
-- approval workflow is enforced (schema now, enforcement later). Entities map every reference as a
-- plain UUID (M1c/M1e precedent); PostgreSQL gets the real foreign keys below. Status varchars are
-- deliberately not value-checked, matching 019-027.

--changeset secy:028a-action-item
--comment one remediation task per row, scoped to one product or one asset; status is the last human decision
create table action_item (
    id                             uuid          not null,
    tenant_id                      uuid          not null,
    title                          varchar(255)  not null,
    description                    varchar(4096),
    product_id                     uuid,
    asset_id                       uuid,
    status                         varchar(16)   not null,
    assignee_id                    uuid,
    created_by_id                  uuid          not null,
    created_at                     timestamp(6)  not null,
    updated_at                     timestamp(6)  not null,
    resolved_at                    timestamp(6),
    risk_accepted_until            timestamp(6),
    risk_accepted_at               timestamp(6),
    risk_accepted_by_id            uuid,
    risk_acceptance_justification  varchar(4096),
    risk_approved_by_id            uuid,
    risk_approval_note             varchar(4096),
    constraint pk_action_item primary key (id),
    constraint fk_action_item_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_action_item_product foreign key (product_id) references products (id) on delete cascade,
    constraint fk_action_item_asset foreign key (asset_id) references asset (id) on delete cascade,
    constraint fk_action_item_assignee foreign key (assignee_id) references app_user (id),
    constraint fk_action_item_created_by foreign key (created_by_id) references app_user (id),
    constraint fk_action_item_risk_accepted_by foreign key (risk_accepted_by_id) references app_user (id),
    constraint fk_action_item_risk_approved_by foreign key (risk_approved_by_id) references app_user (id),
    constraint ck_action_item_one_scope check (num_nonnulls(product_id, asset_id) = 1),
    constraint ck_action_item_title_not_blank check (length(btrim(title)) > 0),
    constraint ck_action_item_resolved_at check (status <> 'RESOLVED' or resolved_at is not null),
    constraint ck_action_item_risk_acceptance check (status <> 'RISK_ACCEPTED' or (
        risk_accepted_until is not null and risk_accepted_at is not null
        and risk_accepted_by_id is not null and risk_acceptance_justification is not null))
);
create index idx_action_item_tenant on action_item (tenant_id);
create index idx_action_item_product_status on action_item (product_id, status);
create index idx_action_item_asset_status on action_item (asset_id, status);
create index idx_action_item_assignee on action_item (assignee_id);
--rollback drop table if exists action_item;

--changeset secy:028b-action-item-finding
--comment links an action item to the findings it remediates; exactly one typed finding column per row, one action item per finding
create table action_item_finding (
    id                                uuid          not null,
    tenant_id                         uuid          not null,
    action_item_id                    uuid          not null,
    finding_type                      varchar(32)   not null,
    vulnerability_alert_id            uuid,
    compromise_finding_id             uuid,
    lifecycle_drift_finding_id        uuid,
    quantum_vulnerability_finding_id  uuid,
    sbom_quality_finding_id           uuid,
    attached_by_id                    uuid          not null,
    attached_at                       timestamp(6)  not null,
    constraint pk_action_item_finding primary key (id),
    constraint fk_action_item_finding_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_action_item_finding_item foreign key (action_item_id) references action_item (id) on delete cascade,
    constraint fk_action_item_finding_vuln_alert foreign key (vulnerability_alert_id) references vulnerability_alert (id) on delete cascade,
    constraint fk_action_item_finding_compromise foreign key (compromise_finding_id) references compromise_finding (id) on delete cascade,
    constraint fk_action_item_finding_drift foreign key (lifecycle_drift_finding_id) references lifecycle_drift_finding (id) on delete cascade,
    constraint fk_action_item_finding_quantum foreign key (quantum_vulnerability_finding_id) references quantum_vulnerability_finding (id) on delete cascade,
    constraint fk_action_item_finding_quality foreign key (sbom_quality_finding_id) references sbom_quality_finding (id) on delete cascade,
    constraint fk_action_item_finding_attached_by foreign key (attached_by_id) references app_user (id),
    constraint ck_action_item_finding_one_target check (num_nonnulls(vulnerability_alert_id, compromise_finding_id,
        lifecycle_drift_finding_id, quantum_vulnerability_finding_id, sbom_quality_finding_id) = 1),
    constraint ck_action_item_finding_type_matches check (
        (finding_type = 'VULNERABILITY')      = (vulnerability_alert_id is not null) and
        (finding_type = 'COMPROMISE')         = (compromise_finding_id is not null) and
        (finding_type = 'LIFECYCLE_DRIFT')    = (lifecycle_drift_finding_id is not null) and
        (finding_type = 'QUANTUM_VULNERABLE') = (quantum_vulnerability_finding_id is not null) and
        (finding_type = 'SBOM_QUALITY')       = (sbom_quality_finding_id is not null)),
    constraint uq_action_item_finding_vuln_alert unique (vulnerability_alert_id),
    constraint uq_action_item_finding_compromise unique (compromise_finding_id),
    constraint uq_action_item_finding_drift unique (lifecycle_drift_finding_id),
    constraint uq_action_item_finding_quantum unique (quantum_vulnerability_finding_id),
    constraint uq_action_item_finding_quality unique (sbom_quality_finding_id)
);
create index idx_action_item_finding_item on action_item_finding (action_item_id);
create index idx_action_item_finding_tenant on action_item_finding (tenant_id);
--rollback drop table if exists action_item_finding;

--changeset secy:028c-action-item-event
--comment append-only action item history; finding_id is deliberately not a foreign key so history outlives a deleted finding
create table action_item_event (
    id                    uuid          not null,
    tenant_id             uuid          not null,
    action_item_id        uuid          not null,
    event_type            varchar(32)   not null,
    from_status           varchar(16),
    to_status             varchar(16),
    derivation            varchar(32),
    finding_type          varchar(32),
    finding_id            uuid,
    assignee_id           uuid,
    risk_accepted_until   timestamp(6),
    risk_approved_by_id   uuid,
    comment               varchar(4096),
    changed_by_id         uuid          not null,
    created_at            timestamp(6)  not null,
    constraint pk_action_item_event primary key (id),
    constraint fk_action_item_event_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_action_item_event_item foreign key (action_item_id) references action_item (id) on delete cascade,
    constraint fk_action_item_event_changed_by foreign key (changed_by_id) references app_user (id)
);
create index idx_action_item_event_item_created on action_item_event (action_item_id, created_at);
--rollback drop table if exists action_item_event;
