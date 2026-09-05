--liquibase formatted sql

-- Baseline of the schema Hibernate previously managed with `ddl-auto=update`.
-- Generated from the JPA entity metamodel with the PostgreSQL dialect
-- (jakarta.persistence.schema-generation.scripts.action=create) and hand-reviewed.
--
-- Existing databases already carry this schema. Mark it as applied instead of
-- running it, e.g.:  liquibase --changelog-file=db/changelog/db.changelog-master.yaml changelog-sync
-- New/empty databases get it applied normally on first boot.

--changeset secy:001-baseline
--comment Baseline schema (20 tables) captured from the Hibernate-managed model

create table cpe_match (
    id varchar(255) not null,
    vulnerable boolean not null,
    criteria varchar(255),
    match_criteria_id varchar(255),
    operator_id varchar(255),
    primary key (id)
);

create table cpe_operator (
    id varchar(255) not null,
    negate boolean not null,
    operator varchar(255),
    cve_id varchar(255),
    primary key (id)
);

create table docker_compliance_report (
    id varchar(255) not null,
    report_id varchar(255),
    title varchar(255),
    description varchar(255),
    version varchar(255),
    primary key (id)
);

create table docker_compliance_report_misconfig (
    id varchar(255) not null,
    type varchar(255),
    avd_id varchar(255),
    title varchar(255),
    description varchar(10024),
    message varchar(255),
    resolution varchar(255),
    severity varchar(255),
    primary_url varchar(255),
    report_id varchar(255),
    primary key (id)
);

create table docker_compliance_report_reference (
    id varchar(255) not null,
    url varchar(255),
    report_id varchar(255),
    primary key (id)
);

create table docker_compliance_report_vulnerability (
    id varchar(255) not null,
    package_name varchar(255),
    version varchar(255),
    fix_version varchar(255),
    vuln_status varchar(255),
    severity_source varchar(255),
    severity varchar(255),
    advisory_url varchar(255),
    title varchar(255),
    description varchar(10024),
    vuln_published_date timestamp(6),
    vuln_last_modified_date timestamp(6),
    report_id varchar(255),
    primary key (id)
);

create table docker_misconfiguration_alert (
    id varchar(255) not null,
    created_date timestamp(6),
    last_modified_date timestamp(6),
    dismissed boolean not null,
    dismissed_reason varchar(255),
    dismissed_evidence_url varchar(255),
    misconfiguration_id varchar(255) unique,
    primary key (id)
);

create table docker_misconfiguration_reference (
    id varchar(255) not null,
    url varchar(255),
    report_id varchar(255),
    primary key (id)
);

-- Table name matches the entity's (misspelled) @Table(name = "docker_vulnerabitity_alert").
create table docker_vulnerabitity_alert (
    id varchar(255) not null,
    created_date timestamp(6),
    last_modified_date timestamp(6),
    dismissed boolean not null,
    dismissed_reason varchar(255),
    dismissed_evidence_url varchar(255),
    vulnerability_id varchar(255) unique,
    primary key (id)
);

create table epss (
    cve varchar(255) not null,
    epss float4 not null,
    percentile float4 not null,
    date timestamp(6),
    primary key (cve)
);

create table kev (
    cve_id varchar(255) not null,
    vendor varchar(255),
    product varchar(255),
    name varchar(255),
    added timestamp(6),
    description varchar(1024),
    required_actions varchar(1024),
    due_date timestamp(6),
    known_ransomware_campaign_use varchar(255),
    notes varchar(1024),
    primary key (cve_id)
);

create table products (
    id uuid not null,
    name varchar(255) not null unique,
    description varchar(1024),
    created_at timestamp(6),
    primary key (id)
);

create table reference (
    id varchar(255) not null,
    url varchar(1024),
    source varchar(255),
    tags varchar(255),
    cve_id varchar(255),
    primary key (id)
);

create table sbom (
    id uuid not null,
    format varchar(255),
    spec_version varchar(255),
    version integer not null,
    product_version varchar(255),
    active boolean not null,
    status varchar(255),
    last_scanned_at timestamp(6),
    upload_date timestamp(6),
    component_id uuid unique,
    product_id uuid,
    primary key (id)
);

create table sbom_component (
    id uuid not null,
    type varchar(255),
    bom_ref varchar(255),
    name varchar(255),
    version varchar(255),
    description varchar(1024),
    purl varchar(255),
    sbom_id uuid,
    primary key (id)
);

create table sbom_license (
    id uuid not null,
    license varchar(255),
    component_id uuid,
    primary key (id)
);

create table sbom_reference (
    id uuid not null,
    type varchar(255),
    url varchar(255),
    component_id uuid,
    primary key (id)
);

create table sbom_tool (
    id uuid not null,
    "group" varchar(255),
    name varchar(255),
    version varchar(255),
    type varchar(255),
    sbom_id uuid,
    primary key (id)
);

create table vulnerabilities (
    id varchar(255) not null,
    source_identifier varchar(255),
    published timestamp(6),
    last_modified timestamp(6),
    vuln_status varchar(255),
    description varchar(10024),
    cve_tags varchar(255),
    base_severity varchar(255),
    access_vector varchar(255),
    access_complexity varchar(255),
    authentication_required varchar(255),
    confidentiality_impact varchar(255),
    integrity_impact varchar(255),
    availability_impact varchar(255),
    cvss_score float(53) not null,
    exploitability_score float(53) not null,
    impact_score float(53) not null,
    can_obtain_all_privilege boolean not null,
    can_obtain_user_privilege boolean not null,
    can_obtain_other_privilege boolean not null,
    user_interaction_required boolean not null,
    cwe varchar(255),
    primary key (id)
);

create table vulnerability_alert (
    id uuid not null,
    vulnerability_id varchar(255),
    component_id uuid,
    primary key (id)
);

alter table cpe_match add constraint FKn22j2m96tilk9b7v5d9wn1dmy foreign key (operator_id) references cpe_operator (id);
alter table cpe_operator add constraint FK6c4sj5noeqr89l8u73h36xrex foreign key (cve_id) references vulnerabilities (id);
alter table docker_compliance_report_misconfig add constraint FKhf1jxa91arhgqwaxw9nrpoi1t foreign key (report_id) references docker_compliance_report (id);
alter table docker_compliance_report_reference add constraint FKfcvd0shuy9e5qghopoi0mcfme foreign key (report_id) references docker_compliance_report (id);
alter table docker_compliance_report_vulnerability add constraint FKbklw1mt9e3unwjkcmx0tmi0v4 foreign key (report_id) references docker_compliance_report (id);
alter table docker_misconfiguration_alert add constraint FKjyaan6kg1f1bo8ufh0q5jts5o foreign key (misconfiguration_id) references docker_compliance_report_misconfig (id);
alter table docker_misconfiguration_reference add constraint FK7vhnxmptswa3oixgl358wme7k foreign key (report_id) references docker_compliance_report_misconfig (id);
alter table docker_vulnerabitity_alert add constraint FK4gqqbdryyhqx48ps4bcngqe03 foreign key (vulnerability_id) references docker_compliance_report_vulnerability (id);
alter table reference add constraint FKbbx98pb0n8xwygm6ph8cqhn6t foreign key (cve_id) references vulnerabilities (id);
alter table sbom add constraint FKcv0pnwjbf41tc95y2msxmq2h0 foreign key (component_id) references sbom_component (id);
alter table sbom add constraint FKdthvf0tiotb6whgi1atmhng3r foreign key (product_id) references products (id);
alter table sbom_component add constraint FK6ph12s663ftb6ikc7sano44uk foreign key (sbom_id) references sbom (id);
alter table sbom_license add constraint FKlw9as1tq85pbmuifl8p2tp10r foreign key (component_id) references sbom_component (id);
alter table sbom_reference add constraint FKpwk9yadaqi60c3ssexc692qnk foreign key (component_id) references sbom_component (id);
alter table sbom_tool add constraint FKgk3dwbs68uwp79q56ovarvqkr foreign key (sbom_id) references sbom (id);
alter table vulnerability_alert add constraint FKpmy6rb3nch9ccq6jktjoj1ydg foreign key (component_id) references sbom_component (id);
alter table vulnerability_alert add constraint FK8xslqk1ad9yiaai46ye5dr31j foreign key (vulnerability_id) references vulnerabilities (id);

--rollback drop table if exists cpe_match;
--rollback drop table if exists cpe_operator;
--rollback drop table if exists docker_compliance_report_reference;
--rollback drop table if exists docker_misconfiguration_reference;
--rollback drop table if exists docker_misconfiguration_alert;
--rollback drop table if exists docker_compliance_report_misconfig;
--rollback drop table if exists docker_vulnerabitity_alert;
--rollback drop table if exists docker_compliance_report_vulnerability;
--rollback drop table if exists docker_compliance_report;
--rollback drop table if exists epss;
--rollback drop table if exists kev;
--rollback drop table if exists reference;
--rollback drop table if exists vulnerability_alert;
--rollback drop table if exists sbom_license;
--rollback drop table if exists sbom_reference;
--rollback drop table if exists sbom_tool;
--rollback drop table if exists sbom_component;
--rollback drop table if exists sbom;
--rollback drop table if exists products;
--rollback drop table if exists vulnerabilities;
