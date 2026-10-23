# Stage 1: build the Java code into target/sbom-pipeline.jar
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -q -B package

# Stage 2: the toolchain - Java + Git + Syft + Grype (team-agreed versions)
FROM eclipse-temurin:17-jre
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
 && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin v1.55.0 \
 && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v0.121.0 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/sbom-pipeline.jar /app/sbom-pipeline.jar
WORKDIR /work
ENTRYPOINT ["java", "-jar", "/app/sbom-pipeline.jar"]
