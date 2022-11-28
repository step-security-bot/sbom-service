plugins {
    id("java")
}

group = "org.opensourceway.sbom"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":clients:vcs"))
    implementation(project(":utils"))

    implementation("org.springframework.boot:spring-boot-starter-webflux")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}