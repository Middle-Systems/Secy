--liquibase formatted sql

-- M1d -- Lineage graph (Apache AGE). See ROADMAP.md's "M1d -- Lineage graph (Apache AGE)": a
-- queryable index over Postgres data, rebuildable from it on demand, never a second source of
-- truth. Both changesets below are precondition-guarded (onFail:CONTINUE) so a Postgres without
-- the AGE extension installed still boots cleanly -- they simply skip (with a warning) on every
-- boot until AGE is installed, then run on the first boot after. Graph labels and indexes are NOT
-- created here -- LineageRebuildService's ensureSchema (via AgeSql.ensureSchemaBlock()) creates
-- them on first rebuild, so new labels added by M1j/M2/M3 need no migration and a dropped graph
-- self-heals. None of this executes under ./gradlew test (H2, Liquibase disabled).

--changeset secy:022a-age-extension
--comment enable Apache AGE when the server has it installed; skipped (re-attempted each boot) otherwise
--preconditions onFail:CONTINUE onError:CONTINUE
--precondition-sql-check expectedResult:1 select count(*) from pg_available_extensions where name = 'age'
create extension if not exists age;
--rollback drop extension if exists age cascade;

--changeset secy:022b-lineage-graph splitStatements:false
--comment create the secy_lineage graph (derived index over Postgres; rebuildable, never a source of truth)
--preconditions onFail:CONTINUE onError:CONTINUE
--precondition-sql-check expectedResult:1 select count(*) from pg_extension where extname = 'age'
do $$
begin
  if not exists (select 1 from ag_catalog.ag_graph where name = 'secy_lineage') then
    perform ag_catalog.create_graph('secy_lineage');
  end if;
end $$;
--rollback select ag_catalog.drop_graph('secy_lineage', true);
