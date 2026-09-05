--liquibase formatted sql

-- Local email + password accounts backing the stateless-JWT auth added in
-- net.jdesive.secy.security / net.jdesive.secy.auth.
--
-- The table is `app_user`, not `user`: `user` is a reserved word in PostgreSQL.
-- `password_hash` holds a BCrypt digest — never a plaintext or reversible value.

--changeset secy:002-auth-users
--comment Local user accounts (email + BCrypt password, USER/ADMIN role)

create table app_user (
    id uuid not null,
    email varchar(255) not null unique,
    password_hash varchar(255) not null,
    display_name varchar(255),
    role varchar(32) not null,
    enabled boolean not null,
    created_at timestamp(6),
    primary key (id)
);

--rollback drop table if exists app_user;
