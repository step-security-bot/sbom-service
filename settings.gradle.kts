rootProject.name = "sbom-service"

pluginManagement {
    val orgSpringframeworkBootVersion: String by settings
    val ioSpringDependencyManagementVersion: String by settings
    plugins {
        id("org.springframework.boot") version orgSpringframeworkBootVersion
        id("io.spring.dependency-management") version ioSpringDependencyManagementVersion
    }
}

includeBuild("sbom-tools/sbom-ort")

include("analyzer")
include("utils")
include("clients:cve-manager")
