FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /app

COPY --from=build /app/target/har-correlation-generator-*.jar app.jar

EXPOSE 80
ENV PORT=80

ENTRYPOINT ["sh", "-c", "java -Dserver.port=${PORT:-80} -jar /app/app.jar"]
