val commonsIoVersion: String by project

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webflux")
//    implementation(project(":utils"))
//    api("commons-io:commons-io:$commonsIoVersion")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}