rootProject.name = "sbom-service"

pluginManagement {
    val orgSpringframeworkBootVersion: String by settings
    val ioSpringDependencyManagementVersion: String by settings
    val kotlinVersion: String by settings
    plugins {
        id("org.springframework.boot") version orgSpringframeworkBootVersion
        id("io.spring.dependency-management") version ioSpringDependencyManagementVersion
        id("org.jetbrains.kotlin.jvm") version kotlinVersion
    }
}

includeBuild("sbom-tools/sbom-ort")

include("analyzer")
include("utils")
include("clients:cve-manager")
include("clients:oss-index")
include("clients:vcs")
include("clients:license")
include("clients:openeuler-repo")
include("clients:sonatype")
include("clients:openharmony-repo")
