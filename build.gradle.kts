import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

private object ProxyArtifactVerification {
    fun expectedHash(metadataFile: File): String = Regex("(?m)^SHA-256: ([a-f0-9]{64})$")
        .find(metadataFile.readText())?.groupValues?.get(1)
        ?: throw GradleException("Missing SHA-256 in $metadataFile")

    fun sha256(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}

abstract class VerifyProxyJarTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val proxySourceFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val proxyJarFile: RegularFileProperty

    @TaskAction
    fun verifyJar() {
        val proxyJar = proxyJarFile.get().asFile
        val expectedHash = ProxyArtifactVerification.expectedHash(proxySourceFile.get().asFile)
        val actualHash = proxyJar.inputStream().use(ProxyArtifactVerification::sha256)
        if (actualHash != expectedHash) {
            throw GradleException("Proxy JAR checksum mismatch: expected $expectedHash, got $actualHash")
        }
    }
}

abstract class VerifyEmbeddedProxyJarTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val extensionJarFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val proxySourceFile: RegularFileProperty

    @TaskAction
    fun verifyEmbeddedJar() {
        val extensionJar = extensionJarFile.get().asFile
        val sourceMetadata = proxySourceFile.get().asFile.readText()
        val expectedHash = ProxyArtifactVerification.expectedHash(proxySourceFile.get().asFile)

        ZipFile(extensionJar).use { zip ->
            val proxyEntry = zip.getEntry("mcp-proxy-all.jar")
                ?: throw GradleException("Missing mcp-proxy-all.jar in $extensionJar")
            val sourceEntry = zip.getEntry("mcp-proxy-source.txt")
                ?: throw GradleException("Missing mcp-proxy-source.txt in $extensionJar")
            val embeddedHash = zip.getInputStream(proxyEntry).use(ProxyArtifactVerification::sha256)
            if (embeddedHash != expectedHash) {
                throw GradleException("Embedded proxy checksum mismatch: expected $expectedHash, got $embeddedHash")
            }
            val embeddedMetadata = zip.getInputStream(sourceEntry).bufferedReader().use { it.readText() }
            if (embeddedMetadata != sourceMetadata) {
                throw GradleException("Embedded proxy source metadata does not match ${proxySourceFile.get().asFile}")
            }
        }

        logger.lifecycle("Verified embedded proxy in ${extensionJar.name}")
    }
}

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktor)
    java
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()
description = providers.gradleProperty("description").get()

dependencies {
    compileOnly(libs.burp.montoya.api)

    implementation(libs.bundles.ktor.server)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.mcp.kotlin.sdk)

    testImplementation(libs.bundles.test.framework)
    testImplementation(libs.bundles.ktor.test)
    testImplementation(libs.burp.montoya.api)
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }

    compilerOptions {
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(
            "-Xjsr305=strict"
        )
    }
}

application {
    mainClass.set("net.portswigger.mcp.ExtensionBase")
}

tasks {
    test {
        useJUnitPlatform()
        systemProperty("file.encoding", "UTF-8")

        testLogging {
            events("passed", "skipped", "failed")
            showExceptions = true
            showCauses = true
            showStackTraces = true
        }
    }

    jar {
        enabled = false
    }

    register<JavaExec>("runConformanceServer") {
        group = "verification"
        description = "Runs the production MCP HTTP endpoint with a deterministic conformance fixture"
        dependsOn(testClasses)
        classpath = sourceSets["test"].runtimeClasspath
        mainClass.set("net.portswigger.mcp.ConformanceServerMainKt")
    }

    val verifyProxyJar = register<VerifyProxyJarTask>("verifyProxyJar") {
        group = "verification"
        description = "Verifies the pinned MCP proxy checksum before packaging"
        proxySourceFile.set(layout.projectDirectory.file("libs/mcp-proxy-source.txt"))
        proxyJarFile.set(layout.projectDirectory.file("libs/mcp-proxy-all.jar"))
    }

    shadowJar {
        dependsOn(verifyProxyJar)
        archiveClassifier.set("")
        mergeServiceFiles()
        from(layout.projectDirectory.file("libs/mcp-proxy-all.jar"))
        from(layout.projectDirectory.file("libs/mcp-proxy-source.txt"))

        manifest {
            attributes(
                mapOf(
                    "Implementation-Title" to project.name,
                    "Implementation-Version" to project.version,
                    "Implementation-Vendor" to "PortSwigger"
                )
            )
        }


        exclude("META-INF/*.SF")
        exclude("META-INF/*.DSA")
        exclude("META-INF/*.RSA")
        exclude("META-INF/INDEX.LIST")
        exclude("META-INF/DEPENDENCIES")
        exclude("META-INF/NOTICE*")
        exclude("META-INF/LICENSE*")
        exclude("module-info.class")

        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    }

    register<VerifyEmbeddedProxyJarTask>("embedProxyJar") {
        group = "build"
        description = "Builds the extension and verifies its embedded MCP proxy"
        dependsOn(shadowJar)
        extensionJarFile.set(shadowJar.flatMap { it.archiveFile })
        proxySourceFile.set(layout.projectDirectory.file("libs/mcp-proxy-source.txt"))
    }

    build {
        dependsOn("embedProxyJar")
    }

    withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
}

tasks.wrapper {
    gradleVersion = "9.2.0"
    distributionType = Wrapper.DistributionType.BIN
}