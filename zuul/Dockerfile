# -----------------------------
# 1) Build stage
# -----------------------------
    FROM gradle:7.5.1-jdk17 AS builder
    # Use the Gradle image with JDK 17 for building (official Gradle image) :contentReference[oaicite:0]{index=0}
    WORKDIR /home/gradle/project
    
    # Cache dependencies: copy only Gradle config first
    COPY settings.gradle settings.gradle
    COPY build.gradle build.gradle
    # If you have custom gradle wrappers or additional config, include them:
    COPY gradle gradle
    COPY gradlew gradlew
    RUN chmod +x gradlew && ./gradlew --version
    
    # Download dependencies offline
    RUN ./gradlew dependency:go-offline --no-daemon
    
    # Copy the Zuul subproject and build just that service
    COPY zuul ./zuul
    RUN ./gradlew :zuul:clean :zuul:bootJar --no-daemon -x test
    
    # -----------------------------
    # 2) Runtime stage
    # -----------------------------
    FROM eclipse-temurin:17-jre-alpine AS runtime
    # Alpine-based Temurin JRE for a minimal, secure runtime :contentReference[oaicite:1]{index=1}
    RUN addgroup -S appgroup && adduser -S appuser -G appgroup
    USER appuser
    
    WORKDIR /app
    
    # Copy the built Zuul fat JAR from the builder stage
    COPY --from=builder /home/gradle/project/zuul/build/libs/zuul-*.jar app.jar
    
    # Expose the Zuul proxy port
    EXPOSE 8060
    
    # Start the application with the Docker profile
    ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar", "--spring.profiles.active=docker"]
    