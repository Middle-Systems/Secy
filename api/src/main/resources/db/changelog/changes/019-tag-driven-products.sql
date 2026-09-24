--liquibase formatted sql

-- M1a -- Tag-driven products. See ROADMAP.md's "M1a -- Tag-driven products": a per-tenant
-- configurable tag key (default 'secy:product'), a real "Unassigned" bucket product per tenant for
-- SBOMs that arrive without that tag, and products.tag_value to record the tag value a product
-- answers to (separate from its display name). Automatic tag extraction from CycloneDX/SPDX
-- documents and connector resource tags is NOT part of this milestone -- see ProductTaggingService.

--changeset secy:019a-product-tag-config
--comment per-tenant product-tag-key configuration, seeded with the default key for every existing tenant

create table product_tag_config (
    id         uuid         not null,
    tenant_id  uuid         not null,
    tag_key    varchar(128) not null,
    created_at timestamp(6) not null,
    updated_at timestamp(6) not null,
    constraint pk_product_tag_config primary key (id),
    constraint uq_product_tag_config_tenant unique (tenant_id),
    constraint fk_product_tag_config_tenant foreign key (tenant_id) references tenant (id),
    constraint ck_product_tag_config_tag_key_format check (tag_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$')
);

-- 'secy:product' must equal ProductTagConfig.DEFAULT_TAG_KEY.
insert into product_tag_config (id, tenant_id, tag_key, created_at, updated_at)
select gen_random_uuid(), id, 'secy:product', now(), now() from tenant;

--rollback drop table if exists product_tag_config;

--changeset secy:019b-products-unassigned-and-tag-value
--comment the Unassigned-bucket flag and the tag value a product answers to, both per-tenant-unique

alter table products add column unassigned boolean not null default false;
alter table products add column tag_value varchar(255);
alter table products add constraint uq_products_tenant_tag_value unique (tenant_id, tag_value);
create unique index uq_products_tenant_unassigned on products (tenant_id) where unassigned;

--rollback drop index if exists uq_products_tenant_unassigned;
--rollback alter table products drop constraint if exists uq_products_tenant_tag_value;
--rollback alter table products drop column tag_value;
--rollback alter table products drop column unassigned;

--changeset secy:019c-unassigned-product-backfill
--comment one Unassigned-bucket product per existing tenant, adopting a pre-existing product literally named 'Unassigned' rather than colliding with uq_products_tenant_name

update products set unassigned = true where name = 'Unassigned';

insert into products (id, tenant_id, name, description, created_at, unassigned)
select gen_random_uuid(), t.id, 'Unassigned',
       'SBOMs that arrived without the tenant''s product tag. Visible to security engineers for triage.',
       now(), true
from tenant t
where not exists (select 1 from products p where p.tenant_id = t.id and p.unassigned);

-- Rollback is best-effort: it only removes a bucket that never received an SBOM, since a bucket
-- holding real SBOMs cannot be dropped without also deciding what happens to them.
--rollback delete from products where unassigned and not exists (select 1 from sbom s where s.product_id = products.id);
