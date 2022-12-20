val packageUrlJavaVersion: String by project
val commonsLang3Version: String by project
val hibernateTypesVersion: String by project

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-xml")
    implementation("com.github.package-url:packageurl-java:$packageUrlJavaVersion")
    implementation("com.vladmihalcea:hibernate-types-55:$hibernateTypesVersion")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}