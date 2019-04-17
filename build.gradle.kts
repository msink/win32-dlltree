plugins {
    kotlin("multiplatform") version "1.3.30"
}

repositories {
    mavenCentral()
}

kotlin {
    mingwX64("windows") {
        compilations["main"].cinterops {
            create("imagehlp")
        }
        binaries.executable {
            entryPoint("ntldd.main")
        }
    }
}
