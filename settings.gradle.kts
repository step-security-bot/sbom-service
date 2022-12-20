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
include("model")
include("dao")
include("clients")
include("interface")
include("cache")
include("quartz")
include("batch")
