val commonsIoVersion: String by project
val commonsLang3Version: String by project

dependencies {
    implementation(project(":clients:vcs"))
    implementation(project(":utils"))

    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-xml")
    implementation("commons-io:commons-io:$commonsIoVersion")
    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.data:spring-data-commons")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}