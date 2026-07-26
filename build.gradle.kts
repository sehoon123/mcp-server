import groovy.json.JsonOutput
import java.io.InputStream
import java.security.MessageDigest
import java.util.jar.Manifest
import java.util.zip.ZipFile
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

private data class ProxyRuntimeComponent(
    val group: String,
    val name: String,
    val version: String,
    val hash: String,
)

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

    fun runtimeComponents(metadataFile: File): List<ProxyRuntimeComponent> {
        val lines = metadataFile.readLines(Charsets.UTF_8)
        val requiredPrefixes = listOf("Source: ", "Commit: ", "Branch: ", "Version: ", "Build: ", "Artifact: ", "SHA-256: ")
        requiredPrefixes.forEach { prefix ->
            if (lines.count { it.startsWith(prefix) } != 1) {
                throw GradleException("Proxy metadata must contain exactly one $prefix entry")
            }
        }
        fun value(prefix: String): String = lines.single { it.startsWith(prefix) }.removePrefix(prefix)
        if (value("Source: ") != "https://github.com/sehoon123/mcp-proxy") {
            throw GradleException("Unexpected proxy source repository")
        }
        if (!value("Commit: ").matches(Regex("^[a-f0-9]{40}$"))) {
            throw GradleException("Proxy source commit is not a full SHA")
        }
        if (value("Branch: ") !in setOf("main", "detached")) {
            throw GradleException("Unexpected proxy source branch")
        }
        if (value("Build: ") != "./gradlew clean test shadowJar writeRuntimeComponents --no-build-cache") {
            throw GradleException("Unexpected proxy build command")
        }
        if (value("Artifact: ") != "build/libs/mcp-proxy-all.jar") {
            throw GradleException("Unexpected proxy artifact path")
        }
        val componentPattern = Regex(
            "^Runtime component: ([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^\\s]+) ([a-f0-9]{64})$"
        )
        val componentLines = lines.filter { it.startsWith("Runtime component:") }
        if (componentLines.isEmpty()) throw GradleException("Proxy metadata contains no runtime components")
        val components = componentLines.map { line ->
            val match = componentPattern.matchEntire(line)
                ?: throw GradleException("Malformed proxy runtime component entry: $line")
            val (group, name, version, hash) = match.destructured
            ProxyRuntimeComponent(group, name, version, hash)
        }
        if (components.distinctBy { listOf(it.group, it.name, it.version) }.size != components.size) {
            throw GradleException("Proxy metadata contains duplicate runtime component coordinates")
        }
        if (lines.size != requiredPrefixes.size + componentLines.size) {
            throw GradleException("Proxy metadata contains blank or unrecognized entries")
        }
        return components
    }
}

private object RuntimeLicensePolicy {
    fun reviewedLicense(licenses: Map<String, String>, group: String, name: String): String =
        licenses["$group:$name"]
            ?: throw GradleException("No reviewed runtime license mapping for Maven coordinate: $group:$name")
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
        val metadataFile = proxySourceFile.get().asFile
        val expectedHash = ProxyArtifactVerification.expectedHash(metadataFile)
        val actualHash = proxyJar.inputStream().use(ProxyArtifactVerification::sha256)
        if (actualHash != expectedHash) {
            throw GradleException("Proxy JAR checksum mismatch: expected $expectedHash, got $actualHash")
        }
        val metadataComponents = ProxyArtifactVerification.runtimeComponents(metadataFile)
        ZipFile(proxyJar).use { zip ->
            val duplicate = zip.entries().asSequence().groupingBy { it.name }.eachCount().entries.firstOrNull { it.value > 1 }
            if (duplicate != null) throw GradleException("Duplicate proxy JAR entry: ${duplicate.key}")

            val manifestEntry = zip.getEntry("META-INF/MANIFEST.MF")
                ?: throw GradleException("Missing proxy manifest")
            val manifest = zip.getInputStream(manifestEntry).use(::Manifest).mainAttributes
            val expectedAttributes = mapOf(
                "Implementation-Title" to "Independent MCP Bridge stdio proxy",
                "Implementation-Vendor" to "sehoon123",
                "Implementation-Source" to "https://github.com/sehoon123/mcp-proxy",
                "Fork-Status" to "Unofficial independent fork; not supported by PortSwigger",
            )
            expectedAttributes.forEach { (name, expected) ->
                if (manifest.getValue(name) != expected) {
                    throw GradleException("Unexpected proxy manifest $name")
                }
            }
            val metadataVersion = Regex("(?m)^Version: ([^\\s]+)$").find(metadataFile.readText())?.groupValues?.get(1)
                ?: throw GradleException("Missing proxy version metadata")
            if (manifest.getValue("Implementation-Version") != metadataVersion) {
                throw GradleException("Proxy manifest version does not match source metadata")
            }

            val requiredEntries = listOf(
                "META-INF/legal/GPL-3.0.txt",
                "META-INF/legal/NOTICE.md",
                "META-INF/legal/FORK_NOTICE.md",
                "META-INF/legal/THIRD_PARTY_NOTICES.md",
                "META-INF/legal/CORRESPONDING_SOURCE.md",
                "META-INF/legal/licenses/Apache-2.0.txt",
                "META-INF/legal/licenses/MIT-SLF4J.txt",
                "META-INF/independent-mcp-bridge/runtime-components.txt",
            )
            requiredEntries.forEach { entry ->
                val zipEntry = zip.getEntry(entry)
                if (zipEntry == null || zipEntry.isDirectory || zipEntry.size <= 0) {
                    throw GradleException("Missing or empty proxy JAR entry: $entry")
                }
            }
            val embeddedComponents = zip.getInputStream(
                zip.getEntry("META-INF/independent-mcp-bridge/runtime-components.txt")
            ).bufferedReader().use { it.readLines() }
            val expectedComponents = metadataComponents.map {
                "${it.group}:${it.name}:${it.version} ${it.hash}"
            }
            if (embeddedComponents != expectedComponents) {
                throw GradleException("Embedded proxy runtime component report does not match source metadata")
            }
        }
    }
}

@CacheableTask
abstract class VerifyLegalBundleTask : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val legalFiles: ConfigurableFileCollection

    @get:Input
    abstract val runtimeArtifactMetadata: ListProperty<String>

    @get:Input
    abstract val reviewedLicenses: MapProperty<String, String>

    @get:Input
    abstract val legalFileHashes: MapProperty<String, String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val proxySourceFile: RegularFileProperty

    @TaskAction
    fun verify() {
        val requiredNames = setOf(
            "LICENSE",
            "FORK_NOTICE.md",
            "NOTICE.md",
            "THIRD_PARTY_NOTICES.md",
            "CORRESPONDING_SOURCE.md",
            "Apache-2.0.txt",
            "MIT-SLF4J.txt",
            "runtime-licenses.properties",
        )
        val filesByName = legalFiles.files.groupBy(File::getName)
        requiredNames.forEach { name ->
            val matches = filesByName[name].orEmpty()
            if (matches.size != 1 || matches.single().length() == 0L) {
                throw GradleException("Required legal file is missing, empty, or ambiguous: $name")
            }
        }

        legalFileHashes.get().forEach { (name, expectedHash) ->
            val file = filesByName[name]?.singleOrNull()
                ?: throw GradleException("Hashed legal file is missing or ambiguous: $name")
            val actualHash = file.inputStream().use(ProxyArtifactVerification::sha256)
            if (actualHash != expectedHash) {
                throw GradleException("Legal file checksum mismatch for $name: expected $expectedHash, got $actualHash")
            }
        }

        val licenses = reviewedLicenses.get()
        val usedCoordinates = mutableSetOf<String>()
        runtimeArtifactMetadata.get().forEach { encoded ->
            val fields = encoded.split('\t')
            if (fields.size != 4) throw GradleException("Invalid runtime artifact metadata entry")
            usedCoordinates += "${fields[1]}:${fields[2]}"
            RuntimeLicensePolicy.reviewedLicense(licenses, fields[1], fields[2])
        }
        ProxyArtifactVerification.runtimeComponents(proxySourceFile.get().asFile).forEach { component ->
            usedCoordinates += "${component.group}:${component.name}"
            RuntimeLicensePolicy.reviewedLicense(licenses, component.group, component.name)
        }
        if (licenses.keys != usedCoordinates) {
            val missing = usedCoordinates - licenses.keys
            val stale = licenses.keys - usedCoordinates
            throw GradleException("Reviewed runtime license map mismatch; missing=$missing stale=$stale")
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

    @get:Input
    abstract val reviewedLicenses: MapProperty<String, String>

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

        val licenses = reviewedLicenses.get()
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
                "licenses" to listOf(mapOf("license" to mapOf("id" to RuntimeLicensePolicy.reviewedLicense(licenses, group, name)))),
                "purl" to reference,
            )
        }.distinctBy { it["bom-ref"] }
            .sortedBy { it["bom-ref"].toString() }
            .toMutableList()
        val extensionDependencyRefs = components.map { it["bom-ref"].toString() }.sorted()

        val metadataFile = proxySourceFile.get().asFile
        val metadata = metadataFile.readText()
        val proxyCommit = Regex("(?m)^Commit: ([a-f0-9]{40})$").find(metadata)?.groupValues?.get(1)
            ?: throw GradleException("Missing source commit in proxy metadata")
        val proxyHash = ProxyArtifactVerification.expectedHash(metadataFile)
        val actualProxyHash = sha256(proxyJarFile.get().asFile)
        if (actualProxyHash != proxyHash) {
            throw GradleException("Proxy JAR checksum mismatch while generating SBOM")
        }
        val proxyReference = "pkg:generic/independent-mcp-bridge-stdio-proxy@$proxyCommit"
        components += linkedMapOf(
            "type" to "application",
            "bom-ref" to proxyReference,
            "name" to "independent-mcp-bridge-stdio-proxy",
            "version" to proxyCommit,
            "hashes" to listOf(mapOf("alg" to "SHA-256", "content" to proxyHash)),
            "licenses" to listOf(mapOf("license" to mapOf("id" to "GPL-3.0-only"))),
            "purl" to proxyReference,
            "properties" to listOf(mapOf("name" to "embedded", "value" to "true")),
        )

        val proxyRuntimeComponents = ProxyArtifactVerification.runtimeComponents(metadataFile)
        val proxyDependencyRefs = proxyRuntimeComponents.map {
            "pkg:maven/${it.group}/${it.name}@${it.version}"
        }.distinct().sorted()
        val existingReferences = components.mapTo(mutableSetOf()) { it["bom-ref"].toString() }
        proxyRuntimeComponents.forEach { component ->
            val (group, name, version, hash) = component
            val reference = "pkg:maven/$group/$name@$version"
            if (existingReferences.add(reference)) {
                components += linkedMapOf(
                    "type" to "library",
                    "bom-ref" to reference,
                    "group" to group,
                    "name" to name,
                    "version" to version,
                    "hashes" to listOf(mapOf("alg" to "SHA-256", "content" to hash)),
                    "licenses" to listOf(mapOf("license" to mapOf("id" to RuntimeLicensePolicy.reviewedLicense(licenses, group, name)))),
                    "purl" to reference,
                    "properties" to listOf(mapOf("name" to "embeddedVia", "value" to "independent-mcp-bridge-stdio-proxy")),
                )
            }
        }
        components.sortBy { it["bom-ref"].toString() }

        val version = rootVersion.get()
        val rootReference = "pkg:generic/independent-mcp-bridge@$version"
        val rootDependencyRefs = (extensionDependencyRefs + proxyReference).distinct().sorted()
        val document = linkedMapOf<String, Any>(
            "bomFormat" to "CycloneDX",
            "specVersion" to "1.6",
            "version" to 1,
            "metadata" to mapOf(
                "component" to linkedMapOf(
                    "type" to "application",
                    "bom-ref" to rootReference,
                    "name" to "independent-mcp-bridge",
                    "version" to version,
                    "hashes" to listOf(
                        mapOf("alg" to "SHA-256", "content" to sha256(extensionJarFile.get().asFile))
                    ),
                    "licenses" to listOf(mapOf("license" to mapOf("id" to "GPL-3.0-only"))),
                    "purl" to rootReference,
                )
            ),
            "components" to components,
            "dependencies" to listOf(
                mapOf("ref" to rootReference, "dependsOn" to rootDependencyRefs),
                mapOf("ref" to proxyReference, "dependsOn" to proxyDependencyRefs),
            ),
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

            val requiredLegalEntries = listOf(
                "META-INF/legal/GPL-3.0.txt",
                "META-INF/legal/NOTICE.md",
                "META-INF/legal/FORK_NOTICE.md",
                "META-INF/legal/THIRD_PARTY_NOTICES.md",
                "META-INF/legal/CORRESPONDING_SOURCE.md",
                "META-INF/legal/licenses/Apache-2.0.txt",
                "META-INF/legal/licenses/MIT-SLF4J.txt",
                "META-INF/legal/runtime-licenses.properties",
            )
            requiredLegalEntries.forEach { entry ->
                if (zip.getEntry(entry) == null) throw GradleException("Missing packaged legal entry: $entry")
            }

            val manifestEntry = zip.getEntry("META-INF/MANIFEST.MF")
                ?: throw GradleException("Missing extension manifest")
            val manifest = zip.getInputStream(manifestEntry).bufferedReader().use { it.readText() }
            if (!manifest.contains("Implementation-Vendor: sehoon123")) {
                throw GradleException("Extension manifest does not identify the independent distributor")
            }
            if (!manifest.contains("Extension-UUID: c0a454c4079c4cecb627d928a92f9555")) {
                throw GradleException("Extension manifest does not contain the independent UUID")
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

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    compileOnly(libs.burp.montoya.api)

    implementation(libs.bundles.ktor.server)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.mcp.kotlin.sdk)

    testImplementation(libs.bundles.test.framework)
    testImplementation(libs.bundles.ktor.test)
    testImplementation(libs.burp.montoya.api)
    testImplementation(platform(libs.jackson.bom.test))
    testImplementation(libs.json.schema.validator)
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
        // Mock-heavy Montoya integration suites can exceed Gradle's 512 MiB worker default on clean CI runners.
        maxHeapSize = "1g"
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
        dependsOn(verifyProxyJar, "verifyLegalBundle")
        archiveClassifier.set("")
        archiveFileName.set("independent-mcp-bridge-all.jar")
        mergeServiceFiles()
        from(layout.projectDirectory.file("libs/mcp-proxy-all.jar"))
        from(layout.projectDirectory.file("libs/mcp-proxy-source.txt"))
        from(layout.projectDirectory.file("LICENSE")) {
            into("META-INF/legal")
            rename { "GPL-3.0.txt" }
        }
        from(layout.projectDirectory.file("NOTICE.md")) { into("META-INF/legal") }
        from(layout.projectDirectory.file("FORK_NOTICE.md")) { into("META-INF/legal") }
        from(layout.projectDirectory.file("THIRD_PARTY_NOTICES.md")) { into("META-INF/legal") }
        from(layout.projectDirectory.file("CORRESPONDING_SOURCE.md")) { into("META-INF/legal") }
        from(layout.projectDirectory.dir("legal/licenses")) { into("META-INF/legal/licenses") }
        from(layout.projectDirectory.file("legal/runtime-licenses.properties")) { into("META-INF/legal") }

        manifest {
            attributes(
                mapOf(
                    "Implementation-Title" to "Independent MCP Bridge",
                    "Implementation-Version" to project.version,
                    "Implementation-Vendor" to "sehoon123",
                    "Implementation-Source" to "https://github.com/sehoon123/mcp-server",
                    "Implementation-Support" to "https://github.com/sehoon123/mcp-server/issues",
                    "Extension-UUID" to "c0a454c4079c4cecb627d928a92f9555",
                    "Fork-Status" to "Unofficial independent fork; not supported by PortSwigger",
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

val runtimeLicensePolicyFile = layout.projectDirectory.file("legal/runtime-licenses.properties")
val reviewedRuntimeLicenses = runtimeLicensePolicyFile.asFile.readLines(Charsets.UTF_8)
    .filter { it.isNotBlank() && !it.startsWith("#") }
    .map { line ->
        val match = Regex("^([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+)=(Apache-2\\.0|MIT)$").matchEntire(line)
            ?: throw GradleException("Invalid reviewed runtime license entry: $line")
        match.groupValues[1] to match.groupValues[2]
    }
    .also { entries ->
        if (entries.map { it.first }.distinct().size != entries.size) {
            throw GradleException("Duplicate coordinate in ${runtimeLicensePolicyFile.asFile}")
        }
    }
    .toMap()

val runtimeSbomArtifacts = configurations.runtimeClasspath.get().incoming.artifacts
val resolvedRuntimeArtifactMetadata = runtimeSbomArtifacts.resolvedArtifacts.map { artifacts ->
    artifacts.map { artifact ->
        val identifier = artifact.id.componentIdentifier
        if (identifier !is ModuleComponentIdentifier) {
            throw GradleException("Unsupported non-module runtime artifact: ${identifier.displayName}")
        }
        listOf(artifact.file.name, identifier.group, identifier.module, identifier.version).joinToString("\t")
    }.sorted()
}

val verifyLegalBundle by tasks.registering(VerifyLegalBundleTask::class) {
    group = "verification"
    description = "Verifies packaged legal files and explicit runtime license mappings."
    legalFiles.from(
        layout.projectDirectory.file("LICENSE"),
        layout.projectDirectory.file("FORK_NOTICE.md"),
        layout.projectDirectory.file("NOTICE.md"),
        layout.projectDirectory.file("THIRD_PARTY_NOTICES.md"),
        layout.projectDirectory.file("CORRESPONDING_SOURCE.md"),
        layout.projectDirectory.file("legal/licenses/Apache-2.0.txt"),
        layout.projectDirectory.file("legal/licenses/MIT-SLF4J.txt"),
        runtimeLicensePolicyFile,
    )
    runtimeArtifactMetadata.set(resolvedRuntimeArtifactMetadata)
    reviewedLicenses.set(reviewedRuntimeLicenses)
    legalFileHashes.set(
        mapOf(
            "LICENSE" to "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
            "Apache-2.0.txt" to "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
            "MIT-SLF4J.txt" to "8e0d2e086db1da82238c27929308de11db7453a29bc0da50331379105e5da8fd",
        )
    )
    proxySourceFile.set(layout.projectDirectory.file("libs/mcp-proxy-source.txt"))
}

val generateSbom by tasks.registering(GenerateSbomTask::class) {
    group = "documentation"
    description = "Generates a deterministic CycloneDX JSON SBOM for the shaded extension and embedded proxy."
    dependsOn("embedProxyJar")

    runtimeArtifactFiles.from(runtimeSbomArtifacts.artifactFiles)
    runtimeArtifactMetadata.set(resolvedRuntimeArtifactMetadata)
    reviewedLicenses.set(reviewedRuntimeLicenses)
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