-- Seeds the default tenant Hibernate's create-drop schema otherwise has no equivalent of migration 018a for. This UUID must match net.jdesive.secy.persistence.entity.Tenant.DEFAULT_TENANT_ID.
insert into tenant (id, name, slug, created_at) values ('00000000-0000-0000-0000-000000000001', 'Default', 'default', current_timestamp);
