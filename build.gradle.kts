import org.jreleaser.model.Active

group = "ru.code4a"
version = file("version").readText().trim()
description =
  "Context-aware cryptography for Quarkus applications, including HKDF-based key derivation, " +
    "authenticated encryption, deterministic encryption, format-preserving encryption, and signing."

plugins {
  val kotlinVersion = "2.4.21"

  kotlin("jvm") version kotlinVersion
  kotlin("plugin.serialization") version kotlinVersion
  kotlin("plugin.allopen") version kotlinVersion
  kotlin("plugin.noarg") version kotlinVersion

  id("org.kordamp.gradle.jandex") version "1.1.0"

  `java-library`
  `maven-publish`
  id("org.jreleaser") version "1.12.0"
}

java {
  withJavadocJar()
  withSourcesJar()
}

publishing {
  publications {
    create<MavenPublication>("mavenJava") {
      artifactId = "quarkus-crypto"

      from(components["java"])

      pom {
        name = "Quarkus Crypto Library"
        description = project.description.toString()
        url = "https://github.com/4ait/quarkus-crypto-lib"
        inceptionYear = "2025"
        licenses {
          license {
            name = "The Apache License, Version 2.0"
            url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
          }
        }
        developers {
          developer {
            id = "tikara"
            name = "Evgeniy Simonenko"
            email = "tiikara93@gmail.com"
            organization.set("4A LLC")
            roles.set(
              listOf(
                "Software Developer",
                "Head of Development"
              )
            )
          }
        }
        organization {
          name = "4A LLC"
          url = "https://4ait.ru"
        }
        scm {
          connection = "scm:git:git://github.com:4ait/quarkus-crypto-lib.git"
          developerConnection = "scm:git:ssh://github.com:4ait/quarkus-crypto-lib.git"
          url = "https://github.com/4ait/quarkus-crypto-lib"
        }
      }
    }
  }
  repositories {
    maven {
      url =
        layout.buildDirectory
          .dir("staging-deploy")
          .get()
          .asFile
          .toURI()
    }
  }
}

repositories {
  mavenCentral()
}

allOpen {
  annotation("jakarta.enterprise.context.ApplicationScoped")
}

tasks.withType<Test> {
  useJUnitPlatform()
  dependsOn(tasks["jandex"])
}

val quarkusVersion: String by project

dependencies {
  // Consumers keep control of their Quarkus platform; do not export forced versions.
  implementation(platform("io.quarkus.platform:quarkus-bom:${quarkusVersion}"))

  implementation("io.quarkus:quarkus-arc")
  api("org.bouncycastle:bcprov-jdk18on")

  implementation("com.google.crypto.tink:tink:1.23.0")
  implementation("org.jetbrains.kotlinx:kotlinx-serialization-core-jvm:1.12.0")
  implementation("org.jetbrains.kotlinx:kotlinx-serialization-protobuf:1.12.0")

  testImplementation(kotlin("test-junit5"))
  testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
  testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named("compileTestKotlin", org.jetbrains.kotlin.gradle.tasks.KotlinCompilationTask::class.java) {
  compilerOptions {
    freeCompilerArgs.add("-Xdebug")
  }
}

jreleaser {
  project {
    copyright.set("4A LLC")
  }
  gitRootSearch.set(true)
  signing {
    active.set(Active.ALWAYS)
    armored.set(true)
  }
  release {
    github {
      overwrite.set(true)
      branch.set("master")
    }
  }
  deploy {
    maven {
      mavenCentral {
        create("maven-central") {
          active.set(Active.ALWAYS)
          url.set("https://central.sonatype.com/api/v1/publisher")
          stagingRepositories.add("build/staging-deploy")
          retryDelay.set(30)
        }
      }
    }
  }
}

kotlin {
  compilerOptions {
    freeCompilerArgs.add("-Xemit-jvm-type-annotations")
  }
}
