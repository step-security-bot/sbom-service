val commonsIoVersion: String by project
val commonsLang3Version: String by project

dependencies {
    implementation(project(":utils"))
    implementation(project(":interface"))
    implementation(project(":model"))
    implementation(project(":cache"))

    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-xml")
    implementation("commons-io:commons-io:$commonsIoVersion")
    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
    implementation("org.apache.httpcomponents.client5:httpclient5:5.1.3")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.data:spring-data-commons")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}
