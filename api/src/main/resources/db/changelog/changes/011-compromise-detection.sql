--liquibase formatted sql

-- Phase 6 — Supply-chain compromise detection (ROADMAP.md).
--
-- The architecture call this phase makes: a "you are shipping something known-bad" finding gets its
-- OWN table (compromise_finding), not a row in vulnerability_alert, and GET /actionable becomes a
-- typed union over the two.
--
-- Why not vulnerability_alert. Every enrichment column on that table is derived from a
-- `vulnerabilities` row: epss_score, cvss_score, kev_due_date, exploit_maturity, fix_state,
-- fixed_versions. A malicious package has no CVE and never will -- there is no score to rank it by,
-- no KEV entry to check, and no fixed release to upgrade to, because the remediation is removal.
-- Putting it in vulnerability_alert would mean a permanently-null second class of row with a null
-- vulnerability_id, breaking the one invariant every Phase 1-5 query relies on, and would force the
-- funnel's KEV/EPSS predicate to special-case rows it structurally cannot evaluate. That is the
-- docker_vulnerabitity_alert mistake (see 010's header) in reverse: not "a parallel table that never
-- reaches the funnel", but "a shared table that breaks the funnel for everyone".
--
-- Why not a second endpoint either. The roadmap's own design puts a compromise finding at the TOP of
-- the same ranked list a KEV-listed CVE is on -- the operator gets one list of what to do next. So:
-- two tables, one screen, a discriminator in the response (ActionableItemResponse.itemType), and the
-- two halves paged by arithmetic over their counts (ActionableService.findActionable).
--
-- What compromise_finding DOES share with vulnerability_alert is where a finding is: the same Phase 4
-- two-nullable-FKs-with-an-XOR pattern (component_id / asset_component_id, check constraint), the
-- same CorrelatableComponent interface, and the same ACTIVE/AUTO_RESOLVED lifecycle. A finding a
-- re-scan no longer reproduces is auto-resolved, never deleted -- Phase 2's rule, unchanged.

--changeset secy:011a-malicious-package-feed
-- OpenSSF Malicious Packages (ossf/malicious-packages), OSV-format, mirrored per
-- (record, ecosystem, package) exactly as osv_advisory is -- correlation always starts from "I have
-- this package", so the row it wants must be findable by (ecosystem, name) alone.
--
-- Not folded into osv_advisory, even though the format is identical, because OsvMatcher requires a
-- CVE- alias to emit anything and a MAL- record has none: every row would be stored and then
-- silently ignored. The tables are also read by different questions -- osv_advisory answers "which
-- advisories affect this version", this one answers "is this package known-bad at all", whose usual
-- answer is "every version of it is".
--
-- No category column value in practice: the published records carry no typo-squat /
-- dependency-confusion classification (every record's CWE is CWE-506 "Embedded Malicious Code").
-- The column is kept for a feed that starts supplying one; `origins` -- the reporting sources from
-- database_specific.malicious-packages-origins[] -- is the discriminator the data actually has, and
-- those entries' modified_time values are what populate ioc_first_seen / ioc_last_seen.
create table malicious_package (
    id               uuid          not null,
    mal_id           varchar(255)  not null,
    ecosystem        varchar(64)   not null,
    package_name     varchar(512)  not null,
    purl             varchar(512),
    summary          varchar(1024),
    details          varchar(10024),
    category         varchar(64),
    origins          varchar(512),
    references_json  varchar(4096),
    published        timestamp(6),
    modified         timestamp(6),
    withdrawn        timestamp(6),
    ioc_first_seen   timestamp(6),
    ioc_last_seen    timestamp(6),
    last_ingested_at timestamp(6),
    constraint pk_malicious_package primary key (id),
    constraint uk_malicious_package_record_package unique (mal_id, ecosystem, package_name)
);

create index idx_malicious_package_lookup on malicious_package (ecosystem, package_name);
create index idx_malicious_package_mal_id on malicious_package (mal_id);

-- The enumerated bad publishes (affected[].versions[]). A hit here is the strongest statement the
-- feed makes about a version and maps to CONFIRMED.
create table malicious_package_version (
    package_id uuid         not null,
    version    varchar(255) not null,
    constraint fk_malicious_package_version_package
        foreign key (package_id) references malicious_package (id)
);

create index idx_malicious_package_version_package on malicious_package_version (package_id);

-- Affected intervals, flattened one-per-row exactly as osv_affected_range is (PHASE2-CONTRACT §1.3).
-- Usually a single unbounded {introduced: "0"} -- the "the whole package is malware" shape.
create table malicious_package_range (
    id            uuid        not null,
    package_id    uuid        not null,
    range_type    varchar(32),
    introduced    varchar(255),
    fixed         varchar(255),
    last_affected varchar(255),
    constraint pk_malicious_package_range primary key (id),
    constraint fk_malicious_package_range_package
        foreign key (package_id) references malicious_package (id)
);

create index idx_malicious_package_range_package on malicious_package_range (package_id);

--rollback drop table if exists malicious_package_range;
--rollback drop table if exists malicious_package_version;
--rollback drop table if exists malicious_package;

--changeset secy:011b-malware-hash-feed
-- abuse.ch MalwareBazaar samples, keyed by SHA-256.
--
-- The digest is the PRIMARY KEY, not a surrogate uuid with a unique index on it. Here the natural
-- key IS the identity: a SHA-256 names exactly one byte sequence, the feed is keyed on it, the match
-- is an equality test against it, and the upsert is "did we already see this digest". A surrogate
-- would add an index nothing ever reads, and it makes the detection hot path a PK lookup.
--
-- last_seen is NOT a column the feed publishes -- the export states first_seen_utc and nothing about
-- currency. It records when an ingest last found the digest in the export, which is what makes IOC
-- aging meaningful: the full export is a complete restatement of the corpus, so "present today" is a
-- live claim and "last present eight months ago" is a decayed one.
create table malware_hash (
    sha256           varchar(64)  not null,
    md5              varchar(32),
    sha1             varchar(40),
    signature        varchar(255),
    file_name        varchar(512),
    file_type        varchar(64),
    mime_type        varchar(128),
    reporter         varchar(128),
    clamav           varchar(255),
    vt_percent       double precision,
    imphash          varchar(64),
    tlsh             varchar(255),
    first_seen       timestamp(6),
    last_seen        timestamp(6),
    confidence       double precision,
    last_ingested_at timestamp(6),
    constraint pk_malware_hash primary key (sha256)
);

create index idx_malware_hash_signature on malware_hash (signature);
create index idx_malware_hash_first_seen on malware_hash (first_seen);

--rollback drop table if exists malware_hash;

--changeset secy:011c-component-hashes
-- Digests a document or scanner declared for a component: CycloneDX hashes[], SPDX checksums[].
--
-- Stored as (algorithm, value) pairs rather than a single sha256 column. Phase 6 only matches
-- SHA-256 -- matching a 128-bit MD5 against a malware corpus is a collision argument nobody wants --
-- but both formats carry a SET of algorithms, and dropping all but one on the way in would mean
-- re-parsing every stored SBOM the day a second hash feed arrives. Storing what the document said
-- costs two small child tables and keeps the parse lossless.
--
-- Both component kinds get one, because CompromiseDetectionService matches through
-- CorrelatableComponent and must not be able to tell them apart -- the same bargain Phase 4 struck.
-- The asset side is structurally supported but unpopulated today: neither TrivyNormalizer nor
-- GrypeNormalizer reads a package-level digest (both derive packages from the scanners'
-- vulnerability entries, which carry a name and version and no checksum). Trivy's Packages[].Digest
-- is where that hook goes.
--
-- No unique constraint on (component, algorithm): a malformed document that lists SHA-256 twice
-- should store both and match once, not fail the whole upload. The Java side is a Set, which dedupes
-- identical pairs already.
create table sbom_component_hash (
    component_id uuid         not null,
    algorithm    varchar(32)  not null,
    hash_value   varchar(128) not null,
    constraint fk_sbom_component_hash_component
        foreign key (component_id) references sbom_component (id)
);

create index idx_sbom_component_hash_component on sbom_component_hash (component_id);
create index idx_sbom_component_hash_value on sbom_component_hash (hash_value);

create table asset_component_hash (
    asset_component_id uuid         not null,
    algorithm          varchar(32)  not null,
    hash_value         varchar(128) not null,
    constraint fk_asset_component_hash_component
        foreign key (asset_component_id) references asset_component (id)
);

create index idx_asset_component_hash_component on asset_component_hash (asset_component_id);
create index idx_asset_component_hash_value on asset_component_hash (hash_value);

--rollback drop table if exists asset_component_hash;
--rollback drop table if exists sbom_component_hash;

--changeset secy:011d-compromise-finding
-- The funnel's third promotion path. See this file's header for why it is its own table.
--
-- severity is a column holding a constant ('CRITICAL' for every row, CompromiseFinding.SEVERITY) and
-- there is deliberately NO secy.compromise.severity knob. Unlike the EPSS threshold, which trades
-- noise against coverage on a continuum, "am I shipping malware" has no continuum to tune. The
-- column exists rather than the value living only in the mapper so a later phase can vary it per
-- type or per source without a migration.
--
-- confidence is its own enum (CONFIRMED/LIKELY/INVESTIGATE), NOT match_confidence's
-- EXACT/RANGE/HEURISTIC. Those bands describe how a version range was evaluated for a CVE; this one
-- has a third state -- decayed -- that the nightly IOC aging sweep writes, and which has no
-- counterpart there. Sharing one enum would have made "matched by a name guess" and "this indicator
-- is eighteen months stale" indistinguishable.
--
-- aged_at records when aging last demoted a row; a non-null value next to INVESTIGATE is how the UI
-- explains why a finding is only worth investigating. Aging demotes and never deletes -- Phase 2's
-- rule again.
create table compromise_finding (
    id                 uuid         not null,
    type               varchar(32)  not null,
    confidence         varchar(16)  not null,
    severity           varchar(16)  not null,
    source             varchar(255) not null,
    ioc_id             varchar(255) not null,
    matched_on         varchar(512) not null,
    summary            varchar(1024),
    details            varchar(10024),
    origins            varchar(512),
    references_json    varchar(4096),
    ioc_first_seen     timestamp(6),
    ioc_last_seen      timestamp(6),
    ioc_confidence     double precision,
    aged_at            timestamp(6),
    component_id       uuid,
    asset_component_id uuid,
    lifecycle_state    varchar(16)  not null,
    last_seen_at       timestamp(6),
    created_at         timestamp(6) not null,
    constraint pk_compromise_finding primary key (id),
    constraint fk_compromise_finding_component
        foreign key (component_id) references sbom_component (id),
    constraint fk_compromise_finding_asset_component
        foreign key (asset_component_id) references asset_component (id)
);

-- The Phase 4 XOR, enforced in the database as well as by the self-clearing Java setters -- the same
-- ck_vuln_alert_one_component constraint migration 009b added, for the same reason: a finding must
-- cite exactly one component, and no code path may create one that cites both or neither.
alter table compromise_finding
    add constraint ck_compromise_finding_one_component
    check (num_nonnulls(component_id, asset_component_id) = 1);

create index idx_compromise_finding_component on compromise_finding (component_id);
create index idx_compromise_finding_asset_component on compromise_finding (asset_component_id);
create index idx_compromise_finding_state on compromise_finding (lifecycle_state);
create index idx_compromise_finding_ioc on compromise_finding (ioc_id);

-- The GET /compromise and GET /actionable sort, and the IOC aging sweep's selection, both lead with
-- lifecycle_state and confidence.
create index idx_compromise_finding_rank on compromise_finding (lifecycle_state, confidence, ioc_last_seen);

--rollback drop table if exists compromise_finding;

--changeset secy:011e-threat-job-types
-- MALICIOUS_PACKAGES and MALWARE_HASHES are singleton feed pulls like NVD/OSV/KEV/EPSS, so unlike
-- SBOM_UPLOAD (008b), ASSET_SCAN (009) and COMPLIANCE_SCAN (010) they KEEP the
-- uq_ingestion_job_active_type slot -- which needs no DDL, because that partial unique index
-- enumerates only the types it EXCLUDES, and these are not among them. One of each runs at a time,
-- and a second POST returns the in-flight job rather than starting a duplicate 310 MB download.
--
-- Two types rather than one shared THREAT type precisely because that constraint is per type:
-- sharing would mean a multi-minute malicious-packages pull blocking a one-second hash refresh.
--
-- What DOES need DDL: ingestion_job.type has been varchar(16) since 003, and 'MALICIOUS_PACKAGES'
-- is 18 characters. Every enum name up to and including COMPLIANCE_SCAN (15) fitted, so this is the
-- first time the cap has bitten. Widened to 32 with room for the next few; Job.type's @Column length
-- is widened to match, which is also what the H2 schema the tests build is generated from.
alter table ingestion_job alter column type type varchar(32);

--rollback alter table ingestion_job alter column type type varchar(16);
