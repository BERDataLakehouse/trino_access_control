plugins {
    `java`
}

// Trino 479 SPI is compiled with Java 25
java {
    sourceCompatibility = JavaVersion.VERSION_25
    targetCompatibility = JavaVersion.VERSION_25
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
