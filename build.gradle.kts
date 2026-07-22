import groovy.json.JsonOutput
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipFile
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

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

@CacheableTask
abstract class GenerateSbomTask : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val runtimeArtifactFiles: ConfigurableFileCollection

    @get:Input
    abstract val runtimeArtifactMetadata: ListProperty<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val proxyJarFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val proxySourceFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val extensionJarFile: RegularFileProperty

    @get:Input
    abstract val rootVersion: Property<String>

    @get:OutputFile
    abstract val outputFile: RegularFileProperty

    @TaskAction
    fun generate() {
        fun sha256(file: File): String = file.inputStream().use(ProxyArtifactVerification::sha256)
        fun licenseFor(group: String): String = if (group == "org.slf4j") "MIT" else "Apache-2.0"

        val artifactsByName = runtimeArtifactFiles.files.groupBy(File::getName)
        val components = runtimeArtifactMetadata.get().map { encoded ->
            val fields = encoded.split('\t')
            if (fields.size != 4) throw GradleException("Invalid runtime artifact metadata entry")
            val (fileName, group, name, version) = fields
            val artifactFiles = artifactsByName[fileName].orEmpty()
            if (artifactFiles.size != 1) {
                throw GradleException("Runtime artifact filename is missing or ambiguous: $fileName")
            }
            val reference = "pkg:maven/$group/$name@$version"
            linkedMapOf<String, Any>(
                "type" to "library",
                "bom-ref" to reference,
                "group" to group,
                "name" to name,
                "version" to version,
                "hashes" to listOf(mapOf("alg" to "SHA-256", "content" to sha256(artifactFiles.single()))),
                "licenses" to listOf(mapOf("license" to mapOf("id" to licenseFor(group)))),
                "purl" to reference,
            )
        }.distinctBy { it["bom-ref"] }
            .sortedBy { it["bom-ref"].toString() }
            .toMutableList()

        val metadataFile = proxySourceFile.get().asFile
        val metadata = metadataFile.readText()
        val proxyCommit = Regex("(?m)^Commit: ([a-f0-9]{40})$").find(metadata)?.groupValues?.get(1)
            ?: throw GradleException("Missing source commit in proxy metadata")
        val proxyHash = ProxyArtifactVerification.expectedHash(metadataFile)
        val actualProxyHash = sha256(proxyJarFile.get().asFile)
        if (actualProxyHash != proxyHash) {
            throw GradleException("Proxy JAR checksum mismatch while generating SBOM")
        }
        val proxyReference = "pkg:generic/burp-mcp-proxy@$proxyCommit"
        components += linkedMapOf(
            "type" to "application",
            "bom-ref" to proxyReference,
            "name" to "burp-mcp-proxy",
            "version" to proxyCommit,
            "hashes" to listOf(mapOf("alg" to "SHA-256", "content" to proxyHash)),
            "licenses" to listOf(mapOf("license" to mapOf("id" to "GPL-3.0-only"))),
            "purl" to proxyReference,
            "properties" to listOf(mapOf("name" to "embedded", "value" to "true")),
        )

        val componentPattern = Regex(
            "(?m)^Runtime component: ([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^\\s]+) ([a-f0-9]{64})$"
        )
        val existingReferences = components.mapTo(mutableSetOf()) { it["bom-ref"].toString() }
        componentPattern.findAll(metadata).forEach { match ->
            val (group, name, version, hash) = match.destructured
            val reference = "pkg:maven/$group/$name@$version"
            if (existingReferences.add(reference)) {
                components += linkedMapOf(
                    "type" to "library",
                    "bom-ref" to reference,
                    "group" to group,
                    "name" to name,
                    "version" to version,
                    "hashes" to listOf(mapOf("alg" to "SHA-256", "content" to hash)),
                    "licenses" to listOf(mapOf("license" to mapOf("id" to licenseFor(group)))),
                    "purl" to reference,
                    "properties" to listOf(mapOf("name" to "embeddedVia", "value" to "burp-mcp-proxy")),
                )
            }
        }
        components.sortBy { it["bom-ref"].toString() }

        val version = rootVersion.get()
        val rootReference = "pkg:generic/burp-mcp-server@$version"
        val dependencyRefs = components.map { it["bom-ref"].toString() }.sorted()
        val document = linkedMapOf<String, Any>(
            "bomFormat" to "CycloneDX",
            "specVersion" to "1.6",
            "version" to 1,
            "metadata" to mapOf(
                "component" to linkedMapOf(
                    "type" to "application",
                    "bom-ref" to rootReference,
                    "name" to "burp-mcp-server",
                    "version" to version,
                    "hashes" to listOf(
                        mapOf("alg" to "SHA-256", "content" to sha256(extensionJarFile.get().asFile))
                    ),
                    "licenses" to listOf(mapOf("license" to mapOf("id" to "GPL-3.0-only"))),
                    "purl" to rootReference,
                )
            ),
            "components" to components,
            "dependencies" to listOf(mapOf("ref" to rootReference, "dependsOn" to dependencyRefs)),
        )
        val destination = outputFile.get().asFile
        destination.parentFile.mkdirs()
        destination.writeText(JsonOutput.prettyPrint(JsonOutput.toJson(document)) + "\n", Charsets.UTF_8)
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
    alias(libs.plugins.shadow)
    application
    java
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()
description = providers.gradleProperty("description").get()

val byteBuddyAgent by configurations.creating

dependencies {
    compileOnly(libs.burp.montoya.api)

    implementation(libs.bundles.ktor.server)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.mcp.kotlin.sdk)

    testImplementation(libs.bundles.test.framework)
    testImplementation(libs.bundles.ktor.test)
    testImplementation(libs.burp.montoya.api)
    byteBuddyAgent(libs.byte.buddy.agent)
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
        jvmArgs("-javaagent:${byteBuddyAgent.singleFile.absolutePath}")

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
        archiveFileName.set("burp-mcp-all.jar")
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

        duplicatesStrategy = DuplicatesStrategy.INCLUDE
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

val runtimeSbomArtifacts = configurations.runtimeClasspath.get().incoming.artifacts
val generateSbom by tasks.registering(GenerateSbomTask::class) {
    group = "documentation"
    description = "Generates a deterministic CycloneDX JSON SBOM for the shaded extension and embedded proxy."
    dependsOn("embedProxyJar")

    runtimeArtifactFiles.from(runtimeSbomArtifacts.artifactFiles)
    runtimeArtifactMetadata.set(runtimeSbomArtifacts.resolvedArtifacts.map { artifacts ->
        artifacts.map { artifact ->
            val identifier = artifact.id.componentIdentifier
            if (identifier !is ModuleComponentIdentifier) {
                throw GradleException("Unsupported non-module runtime artifact: ${identifier.displayName}")
            }
            listOf(artifact.file.name, identifier.group, identifier.module, identifier.version).joinToString("\t")
        }.sorted()
    })
    proxyJarFile.set(layout.projectDirectory.file("libs/mcp-proxy-all.jar"))
    proxySourceFile.set(layout.projectDirectory.file("libs/mcp-proxy-source.txt"))
    extensionJarFile.set(
        tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar")
            .flatMap { it.archiveFile }
    )
    rootVersion.set(providers.gradleProperty("version"))
    outputFile.set(layout.buildDirectory.file("reports/compliance/bom.cdx.json"))
}

tasks.wrapper {
    gradleVersion = "9.2.0"
    distributionType = Wrapper.DistributionType.BIN
}