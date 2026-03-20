# Multi-stage build: compile plugin JAR then copy into Trino image
# Same builder pattern as spark_notebook_base and hive_metastore

# ARG before any FROM so it's available in FROM instructions
ARG TRINO_VERSION=479

FROM gradle:9.4.0-jdk25-ubi AS builder
WORKDIR /build
COPY build.gradle.kts settings.gradle.kts ./
COPY src/ src/
RUN gradle jar --no-daemon

FROM trinodb/trino:${TRINO_VERSION}

# Install plugin JAR into Trino's plugin directory
COPY --from=builder /build/libs/berdl-trino-access-control-1.0.0.jar \
    /usr/lib/trino/plugin/berdl-access-control/
