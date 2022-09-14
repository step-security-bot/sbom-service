val commonsIoVersion: String by project

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation(project(":utils"))
    implementation("org.apache.httpcomponents.client5:httpclient5:5.1.3")
    api("commons-io:commons-io:$commonsIoVersion")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}