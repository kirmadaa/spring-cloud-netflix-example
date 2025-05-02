# 1) Build stage: uses official Gradle (multi-arch) with JDK 17
FROM gradle:7.5.1-jdk17 AS builder
WORKDIR /home/gradle/project

# Cache Gradle metadata
COPY settings.gradle build.gradle gradlew ./
COPY gradle/ gradle/
RUN chmod +x gradlew && ./gradlew dependency:go-offline --no-daemon

# Build only the Zuul subproject
COPY ../zuul/ zuul/
RUN ./gradlew :zuul:clean :zuul:bootJar --no-daemon -x test

# 2) Runtime stage: switch off Alpine for ARM64 compatibility
# Option A: Temurin non-Alpine (Debian/Ubuntu-based, multi-arch) 
FROM eclipse-temurin:17-jre AS runtime
# └─ This image supports both amd64 and arm64 :contentReference[oaicite:3]{index=3}

# (Or, Option B: Alpine-musl via BellSoft if you really need Alpine)
# FROM bellsoft/liberica-openjdk-alpine-musl:17 AS runtime
# This provides Alpine/musl for AArch64 :contentReference[oaicite:4]{index=4}

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

WORKDIR /app
# Copy the fat JAR from the builder
COPY --from=builder /home/gradle/project/zuul/build/libs/zuul-*.jar app.jar

EXPOSE 8060
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","app.jar","--spring.profiles.active=docker"]
