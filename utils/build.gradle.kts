val commonsCompressVersion: String by project
val packageUrlJavaVersion: String by project

dependencies {
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-xml")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml")
    implementation("org.apache.commons:commons-compress:$commonsCompressVersion")
    implementation("com.github.package-url:packageurl-java:$packageUrlJavaVersion")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework:spring-context-support:5.3.23")
    implementation("org.yaml:snakeyaml")

    api("com.github.ben-manes.caffeine:caffeine")
    api("com.google.guava:guava:31.1-jre")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}