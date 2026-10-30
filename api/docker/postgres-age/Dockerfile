# Apache AGE (graph extension for Postgres) layered onto the stock postgres:16 image, for M1d's
# lineage graph (ROADMAP.md, M1d -- "Lineage graph (Apache AGE)").
#
# Why build on postgres:16 rather than pulling `apache/age` directly: postgres:16 is the same
# Debian/glibc base image api/compose.yaml (and docker-compose.yml) already used to create most
# users' existing `secy-pgdata` volume. Switching the base image family on an existing data
# directory risks a collation-version mismatch Postgres will refuse to start against. Building
# postgresql-16-age on top of the exact image already in use avoids that entirely.
#
# The `age` extension itself is created by Liquibase changesets 022a/022b -- NOT by an initdb
# script here -- specifically so an EXISTING data volume (created before this Dockerfile existed)
# picks up AGE on its next boot too, the same as a brand new one. An initdb script only runs
# against a freshly-initialized, empty data directory.
#
# Documented fallback, if this base-image approach ever proves wrong for your setup: switch to the
# official `image: apache/age:release_PG16_1.6.0` (a bind mount, not a build). Take a `pg_dump`
# first if you do -- its base image may not be the same Debian release as `postgres:16`, so the
# same collation-mismatch risk applies in the other direction.
FROM postgres:16

RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-16-age \
 && rm -rf /var/lib/apt/lists/*

CMD ["postgres", "-c", "shared_preload_libraries=age"]
