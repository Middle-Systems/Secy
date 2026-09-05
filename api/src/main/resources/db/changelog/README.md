# Database migrations

Schema changes are managed by [Liquibase](https://docs.liquibase.com/). Hibernate no longer owns the
schema: `spring.jpa.hibernate.ddl-auto=validate`, so the entity model is checked against whatever
Liquibase built, and a mismatch fails startup instead of silently altering tables.

## Layout

```
db/changelog/
  db.changelog-master.yaml   <- includeAll over changes/ — DO NOT EDIT to add a migration
  changes/
    001-baseline.sql         <- schema as of the ddl-auto=update era
    002-....sql              <- your changeset goes here
```

`db.changelog-master.yaml` uses `includeAll`, so **every file dropped in `changes/` is picked up
automatically**. Adding a migration means adding one new file — never editing the master changelog.
That keeps parallel branches from colliding on a shared file.

## Naming convention

`NNN-short-description.sql` (or `.yaml`)

- `NNN` — a zero-padded three-digit sequence number, unique across the directory.
- `short-description` — lowercase, hyphen-separated (`002-auth-users`, `003-ingestion-queue`).
- `includeAll` sorts files by name, so the zero-padding is what guarantees execution order.
  `010-*` must not become `10-*`.

Claimed prefixes:

| Prefix | Owner |
|--------|-------|
| `001`  | baseline schema (this branch) |
| `002`  | auth |
| `003`  | ingestion queue |

Pick the next free number if yours isn't listed.

## Writing a changeset

Formatted SQL files need the header and at least one changeset directive:

```sql
--liquibase formatted sql

--changeset secy:002-auth-users
create table app_user (...);

--rollback drop table if exists app_user;
```

Rules of thumb:

- Author id is `secy`; changeset id matches the file's `NNN-description`.
- One logical change per changeset; add a `--rollback` where a sensible inverse exists.
- **Never edit a changeset that has shipped.** Liquibase checksums applied changesets and a modified
  one fails on startup. Correct it with a new numbered file.
- Target dialect is PostgreSQL (see the testing note below).

## Baseline

`001-baseline.sql` was generated from the JPA entity metamodel with the PostgreSQL dialect
(`jakarta.persistence.schema-generation.scripts.action=create`) and hand-reviewed. It reproduces the
20 tables Hibernate had been creating under `ddl-auto=update`.

A database that already ran under `ddl-auto=update` **already has these tables**. Mark the baseline
as applied rather than running it:

```bash
liquibase --changelog-file=db/changelog/db.changelog-master.yaml changelog-sync
```

A fresh/empty database just applies it on first boot.

## Testing

Tests run against H2 with `spring.liquibase.enabled=false` and
`spring.jpa.hibernate.ddl-auto=create-drop` (see `src/test/resources/application.properties`) — the
schema under test is built by Hibernate from the entities, not by Liquibase. That keeps the test
suite fully offline and lets the changesets stay Postgres-dialect (`float4`, `uuid`, `timestamp(6)`,
quoted `"group"`), which H2 would not accept verbatim.

Gotcha: `src/test/resources/application.properties` **replaces** `src/main/resources/application.properties`
outright — it does not merge with it. Spring resolves `classpath:application.properties` to the first
match on the classpath, and test resources come first, so any main-profile-only key reads back as
`null` under test. If you add a property to the main file that your `@SpringBootTest` needs, add it
to the test file too.

The consequence: **the changelog itself is not exercised by `./gradlew test`.** Verify it against a
real PostgreSQL before merging — e.g. point `SECY_DB_URL` at a scratch database and boot the app, or
run `liquibase update` against it. `ddl-auto=validate` in the main profile is the safety net: if a
changeset and the entities disagree, the app refuses to start.
