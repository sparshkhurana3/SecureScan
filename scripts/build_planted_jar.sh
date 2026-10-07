#!/bin/sh
# Builds backend/tests/fixtures/sample-apps/java-planted/target/java-planted.jar with Maven in a container,
# so no JDK is needed on the host. Commit the resulting jar (SpotBugs analyses compiled classes).
set -eu
APP="$(cd "$(dirname "$0")/.." && pwd)/backend/tests/fixtures/sample-apps/java-planted"
docker run --rm -u "$(id -u):$(id -g)" -v "$APP":/app -w /app -e MAVEN_CONFIG=/tmp/.m2 \
  maven:3.9-eclipse-temurin-21 mvn -q -Dmaven.repo.local=/tmp/.m2/repository -DskipTests package
ls -l "$APP/target/java-planted.jar"
