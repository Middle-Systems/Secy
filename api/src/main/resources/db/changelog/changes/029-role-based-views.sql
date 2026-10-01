--liquibase formatted sql

-- M1k -- Role-based views. Data model only; enforcement is Tenancy hardening's job. Entities map
-- access_updated_by_id and vex_document_id as plain UUIDs (M1c/M1e/M1j precedent); Postgres gets
-- real foreign keys. Role values are deliberately not CHECK-constrained, matching 019-028.

--changeset secy:029a-tenant-membership-access
--comment per-tenant tenant-admin permission and role bookkeeping on the existing membership row
alter table tenant_membership add column tenant_admin boolean not null default false;
alter table tenant_membership add column roles_configured boolean not null default false;
alter table tenant_membership add column access_updated_at timestamp(6);
alter table tenant_membership add column access_updated_by_id uuid;
alter table tenant_membership add constraint fk_tenant_membership_access_updated_by
    foreign key (access_updated_by_id) references app_user (id) on delete set null;
--rollback alter table tenant_membership drop constraint if exists fk_tenant_membership_access_updated_by;
--rollback alter table tenant_membership drop column if exists access_updated_by_id;
--rollback alter table tenant_membership drop column if exists access_updated_at;
--rollback alter table tenant_membership drop column if exists roles_configured;
--rollback alter table tenant_membership drop column if exists tenant_admin;

--changeset secy:029b-tenant-membership-role
--comment the view roles (LEADERSHIP / SECURITY_ENGINEER / SOFTWARE_ENGINEER) one membership holds; 0-N per membership.
--comment Satellite entity (own id, plain membership_id with no JPA relation) rather than an
--comment @ElementCollection -- Hibernate 6.5.3 rejects @OnDelete on an @ElementCollection mapped via
--comment @CollectionTable, so TenantMembership itself never carries a FK-generating relation to this
--comment table; Postgres still gets a real cascade below.
create table tenant_membership_role (
    id            uuid        not null,
    membership_id uuid        not null,
    role          varchar(32) not null,
    constraint pk_tenant_membership_role primary key (id),
    constraint uq_tenant_membership_role unique (membership_id, role),
    constraint fk_tenant_membership_role_membership foreign key (membership_id)
        references tenant_membership (id) on delete cascade
);
--rollback drop table if exists tenant_membership_role;

--changeset secy:029c-action-item-event-vex-document
--comment links a DISPUTED action-item event to the authored VEX document it queued
alter table action_item_event add column vex_document_id uuid;
alter table action_item_event add constraint fk_action_item_event_vex_document
    foreign key (vex_document_id) references vex_document (id) on delete set null;
--rollback alter table action_item_event drop constraint if exists fk_action_item_event_vex_document;
--rollback alter table action_item_event drop column if exists vex_document_id;
