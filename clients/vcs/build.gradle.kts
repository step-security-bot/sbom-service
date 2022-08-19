val commonsLang3Version: String by project

dependencies {
    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
    implementation("org.springframework.boot:spring-boot-starter-webflux")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}