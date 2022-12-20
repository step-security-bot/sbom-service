val commonsLang3Version: String by project

dependencies {
    implementation(project(":model"))

    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.postgresql:postgresql")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}