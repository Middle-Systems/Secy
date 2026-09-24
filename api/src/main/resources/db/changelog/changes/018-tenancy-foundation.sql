--liquibase formatted sql

-- M0 -- Tenancy foundation (schema only). See ROADMAP.md's "M0 -- Tenancy foundation (schema
-- only)": this migration lands Tenant + tenant_id everywhere the roadmap requires, backfilled onto
-- one default tenant so the branch keeps working single-tenant through M1 without every query
-- needing a tenant filter yet. Enforcement (Postgres row-level security, per-tenant KMS, SSO, the
-- audit log, query-level tenant filtering) is a dedicated "Tenancy hardening" milestone, not this
-- one -- tenant_id existing on a row here is not the same as it being enforced.

--changeset secy:018a-tenant
--comment the tenant table, seeded with the one default tenant every existing row is attributed to

create table tenant (
    id         uuid         not null,
    name       varchar(255) not null,
    slug       varchar(63)  not null,
    created_at timestamp(6) not null,
    constraint pk_tenant primary key (id),
    constraint uq_tenant_slug unique (slug),
    constraint ck_tenant_slug_format check (slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$')
);

-- This UUID must equal net.jdesive.secy.persistence.entity.Tenant.DEFAULT_TENANT_ID.
insert into tenant (id, name, slug, created_at)
values ('00000000-0000-0000-0000-000000000001', 'Default', 'default', now());

--rollback drop table if exists tenant;

--changeset secy:018b-tenant-membership
--comment user <-> tenant join table, backfilled with a default-tenant membership for every existing account

create table tenant_membership (
    id         uuid         not null,
    tenant_id  uuid         not null,
    user_id    uuid         not null,
    created_at timestamp(6) not null,
    constraint pk_tenant_membership primary key (id),
    constraint uq_tenant_membership_tenant_user unique (tenant_id, user_id),
    constraint fk_tenant_membership_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_tenant_membership_user foreign key (user_id) references app_user (id) on delete cascade
);

create index idx_tenant_membership_user on tenant_membership (user_id);

insert into tenant_membership (id, tenant_id, user_id, created_at)
select gen_random_uuid(), '00000000-0000-0000-0000-000000000001', id, now() from app_user;

--rollback drop table if exists tenant_membership;

--changeset secy:018c-tenant-id-columns
--comment tenant_id on every table this roadmap milestone touches, backfilled onto the default tenant

alter table products add column tenant_id uuid;
update products set tenant_id = '00000000-0000-0000-0000-000000000001' where tenant_id is null;
alter table products alter column tenant_id set not null;
alter table products add constraint fk_products_tenant foreign key (tenant_id) references tenant (id);

alter table sbom add column tenant_id uuid;
update sbom set tenant_id = '00000000-0000-0000-0000-000000000001' where tenant_id is null;
alter table sbom alter column tenant_id set not null;
alter table sbom add constraint fk_sbom_tenant foreign key (tenant_id) references tenant (id);

alter table asset add column tenant_id uuid;
update asset set tenant_id = '00000000-0000-0000-0000-000000000001' where tenant_id is null;
alter table asset alter column tenant_id set not null;
alter table asset add constraint fk_asset_tenant foreign key (tenant_id) references tenant (id);

alter table vulnerability_alert add column tenant_id uuid;
update vulnerability_alert set tenant_id = '00000000-0000-0000-0000-000000000001' where tenant_id is null;
alter table vulnerability_alert alter column tenant_id set not null;
alter table vulnerability_alert add constraint fk_vuln_alert_tenant foreign key (tenant_id) references tenant (id);

alter table compromise_finding add column tenant_id uuid;
update compromise_finding set tenant_id = '00000000-0000-0000-0000-000000000001' where tenant_id is null;
alter table compromise_finding alter column tenant_id set not null;
alter table compromise_finding add constraint fk_compromise_finding_tenant foreign key (tenant_id) references tenant (id);

alter table source_connector add column tenant_id uuid;
update source_connector set tenant_id = '00000000-0000-0000-0000-000000000001' where tenant_id is null;
alter table source_connector alter column tenant_id set not null;
alter table source_connector add constraint fk_source_connector_tenant foreign key (tenant_id) references tenant (id);

alter table docker_compliance_report add column tenant_id uuid;
update docker_compliance_report set tenant_id = '00000000-0000-0000-0000-000000000001' where tenant_id is null;
alter table docker_compliance_report alter column tenant_id set not null;
alter table docker_compliance_report add constraint fk_docker_compliance_report_tenant foreign key (tenant_id) references tenant (id);

-- products and asset get their tenant_id index for free from the composite unique constraints
-- added in 018e; the rest need one of their own since nothing else leads with tenant_id.
create index idx_sbom_tenant on sbom (tenant_id);
create index idx_vuln_alert_tenant on vulnerability_alert (tenant_id);
create index idx_compromise_finding_tenant on compromise_finding (tenant_id);
create index idx_source_connector_tenant on source_connector (tenant_id);
create index idx_docker_compliance_report_tenant on docker_compliance_report (tenant_id);

-- No column default is left on any tenant_id: the JPA @PrePersist on TenantOwnedEntity is the only
-- defaulting mechanism from here on.

--rollback drop index if exists idx_docker_compliance_report_tenant;
--rollback alter table docker_compliance_report drop constraint if exists fk_docker_compliance_report_tenant;
--rollback alter table docker_compliance_report drop column tenant_id;
--rollback drop index if exists idx_source_connector_tenant;
--rollback alter table source_connector drop constraint if exists fk_source_connector_tenant;
--rollback alter table source_connector drop column tenant_id;
--rollback drop index if exists idx_compromise_finding_tenant;
--rollback alter table compromise_finding drop constraint if exists fk_compromise_finding_tenant;
--rollback alter table compromise_finding drop column tenant_id;
--rollback drop index if exists idx_vuln_alert_tenant;
--rollback alter table vulnerability_alert drop constraint if exists fk_vuln_alert_tenant;
--rollback alter table vulnerability_alert drop column tenant_id;
--rollback alter table asset drop constraint if exists fk_asset_tenant;
--rollback alter table asset drop column tenant_id;
--rollback alter table sbom drop constraint if exists fk_sbom_tenant;
--rollback alter table sbom drop column tenant_id;
--rollback alter table products drop constraint if exists fk_products_tenant;
--rollback alter table products drop column tenant_id;

--changeset secy:018d-drop-global-product-name-unique splitStatements:false
--comment drop products' old global unique-on-name constraint, whatever it happens to be named

-- splitStatements:false is required here (the first use of this directive in this repo) because the
-- PL/pgSQL block below contains semicolons of its own; Liquibase's default statement splitter would
-- otherwise cut the block apart at them. The constraint's name is not knowable in advance: on a
-- database built straight from 001-baseline.sql it is the inline-declared "products_name_key", but
-- on a database that ran under Hibernate ddl-auto=update before Liquibase took over and was then
-- changelog-sync'd (see the changelog README's "Baseline" section), it is a Hibernate-generated
-- "uk..." hash instead. So: look it up from the catalog rather than hardcoding a name.
do $$
declare c text;
begin
  for c in
    select con.conname
    from pg_constraint con
    join pg_class rel on rel.oid = con.conrelid
    join pg_attribute att on att.attrelid = rel.oid and att.attnum = con.conkey[1]
    where rel.relname = 'products' and con.contype = 'u'
      and array_length(con.conkey, 1) = 1 and att.attname = 'name'
  loop
    execute format('alter table products drop constraint %I', c);
  end loop;
end $$;

--rollback alter table products add constraint products_name_key unique (name);

--changeset secy:018e-tenant-scoped-unique-constraints
--comment replace the now-dropped global product-name uniqueness and the global asset (type, name) uniqueness with tenant-scoped equivalents

alter table products add constraint uq_products_tenant_name unique (tenant_id, name);
alter table asset drop constraint uq_asset_type_name;
alter table asset add constraint uq_asset_tenant_type_name unique (tenant_id, type, name);

--rollback alter table asset drop constraint if exists uq_asset_tenant_type_name;
--rollback alter table asset add constraint uq_asset_type_name unique (type, name);
--rollback alter table products drop constraint if exists uq_products_tenant_name;
