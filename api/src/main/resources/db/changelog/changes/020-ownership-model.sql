--liquibase formatted sql

-- M1b -- Ownership model. See ROADMAP.md's "M1b -- Ownership model": ownership links from a
-- product (or, from M3 on, an asset) to an owner -- a registered user, or a free-text principal
-- (GitHub login, email, team name) that inference sources emit. Every link records its source
-- (MANUAL / INFERRED); only MANUAL is written in M1b. M2 (CODEOWNERS, GitHub team permissions) and
-- M3 (cloud resource owner tags) add INFERRED rows with no schema change -- inference_method is a
-- free varchar mapped to a Java enum, deliberately not value-checked here.

--changeset secy:020a-ownership-link
--comment ownership links: exactly one target (product or asset), a USER or TEAM owner, and the source that asserted it

create table ownership_link (
    id               uuid          not null,
    tenant_id        uuid          not null,
    product_id       uuid,
    asset_id         uuid,
    owner_type       varchar(16)   not null,
    user_id          uuid,
    principal        varchar(255),
    source           varchar(16)   not null,
    inference_method varchar(32),
    evidence         varchar(1024),
    assigned_by_id   uuid,
    created_at       timestamp(6)  not null,
    constraint pk_ownership_link primary key (id),
    constraint fk_ownership_link_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_ownership_link_product foreign key (product_id) references products (id) on delete cascade,
    constraint fk_ownership_link_asset foreign key (asset_id) references asset (id) on delete cascade,
    constraint fk_ownership_link_user foreign key (user_id) references app_user (id) on delete cascade,
    constraint fk_ownership_link_assigned_by foreign key (assigned_by_id) references app_user (id) on delete set null,
    constraint ck_ownership_link_one_target check (num_nonnulls(product_id, asset_id) = 1),
    constraint ck_ownership_link_owner_shape check (
        (owner_type = 'USER' and num_nonnulls(user_id, principal) >= 1)
        or (owner_type = 'TEAM' and user_id is null and principal is not null)),
    constraint ck_ownership_link_principal_not_blank check (principal is null or length(btrim(principal)) > 0),
    constraint ck_ownership_link_source_method check (
        (source = 'MANUAL' and inference_method is null)
        or (source = 'INFERRED' and inference_method is not null)),
    constraint ck_ownership_link_manual_user_registered check (
        source <> 'MANUAL' or owner_type <> 'USER' or user_id is not null)
);

--rollback drop table if exists ownership_link;

--changeset secy:020b-ownership-link-indexes
--comment one link per (target, owner, source, inference method); lookup indexes for M1k's per-user product filter

create unique index uq_ownership_link_product_owner on ownership_link
    (product_id, owner_type, coalesce(user_id::text, lower(principal)), source, coalesce(inference_method, ''))
    where product_id is not null;
create unique index uq_ownership_link_asset_owner on ownership_link
    (asset_id, owner_type, coalesce(user_id::text, lower(principal)), source, coalesce(inference_method, ''))
    where asset_id is not null;
create index idx_ownership_link_tenant on ownership_link (tenant_id);
create index idx_ownership_link_user on ownership_link (user_id) where user_id is not null;

--rollback drop index if exists idx_ownership_link_user;
--rollback drop index if exists idx_ownership_link_tenant;
--rollback drop index if exists uq_ownership_link_asset_owner;
--rollback drop index if exists uq_ownership_link_product_owner;
