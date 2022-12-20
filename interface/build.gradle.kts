val commonsLang3Version: String by project

dependencies {
    implementation(project(":model"))

    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.data:spring-data-commons")
    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}