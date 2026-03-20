plugins {
    `java`
}

// Target Java 17 — compatible with Trino 479's Java 23 runtime
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

// Must match the Trino server version (trinodb/trino:<version> in docker-compose)
val trinoVersion = "479"

repositories {
    mavenCentral()
}

dependencies {
    // Trino SPI — provided at runtime by the Trino server
    compileOnly("io.trino:trino-spi:$trinoVersion")
}

tasks.jar {
    archiveBaseName.set("berdl-trino-access-control")
    archiveVersion.set("1.0.0")
    destinationDirectory.set(file("libs"))
}
