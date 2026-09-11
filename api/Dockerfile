# syntax=docker/dockerfile:1
#
# Multi-stage build for the Secy API (Spring Boot 3.3.4 / Java 17).
#
# Build stage produces a bootable jar with the Gradle wrapper; runtime stage is a slim
# JRE-only image that just runs that jar. Tests are NOT re-run here (`bootJar`, not
# `build`) — the CI workflow (`.github/workflows/ci.yml`) already runs `./gradlew build`
# (compile + full test suite) on every push/PR, so re-running them again during the image
# build would only slow down `docker build` without adding a new signal. If you build this
# image directly (skipping CI), run `./gradlew test` yourself first.

# --- Build stage -------------------------------------------------------------------
FROM eclipse-temurin:17-jdk-jammy AS build
WORKDIR /workspace

# Gradle wrapper + build scripts first so `./gradlew bootJar` (and its dependency
# resolution) is cached in its own layer as long as these files don't change.
COPY gradlew ./
COPY gradle ./gradle
COPY build.gradle settings.gradle ./
RUN chmod +x gradlew && ./gradlew --version --no-daemon

# Now the rest of the sources.
COPY src ./src

RUN ./gradlew bootJar --no-daemon -x test

# --- Runtime stage -------------------------------------------------------------------
FROM eclipse-temurin:17-jre-jammy AS runtime

# The base actuator starter only exposes `health` over HTTP by default (see
# application.properties — no management.endpoints.web.exposure.include override), and
# SecurityConfig permits `/actuator/health` anonymously, so curl needs no auth header.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system secy && useradd --system --gid secy --home-dir /app --shell /usr/sbin/nologin secy
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar /app/app.jar
RUN chown -R secy:secy /app
USER secy

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=45s --retries=5 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
