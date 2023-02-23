val commonsLang3Version: String by project
val commonsCollections4Version: String by project
val packageUrlJavaVersion: String by project

dependencies {
    implementation(project(":model"))
    implementation(project(":interface"))
    implementation(project(":dao"))
    implementation(project(":cache"))
    implementation(project(":utils"))

    implementation("oss-review-toolkit:model")
    implementation("oss-review-toolkit:utils:spdx-utils")

    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
    implementation("org.apache.commons:commons-collections4:$commonsCollections4Version")
    implementation("com.github.package-url:packageurl-java:$packageUrlJavaVersion")
    implementation("org.springframework.boot:spring-boot-starter-batch")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}