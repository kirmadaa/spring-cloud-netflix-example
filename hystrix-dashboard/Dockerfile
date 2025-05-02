FROM openjdk:11
RUN mkdir /app
WORKDIR /app
COPY build/libs/hystrix-dashboard.jar /app
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/hystrix-dashboard.jar", "--spring.profiles.active=docker"]
EXPOSE 8050