#!/usr/bin/env bash
# Builds the Java oracle used by the parity / e2e tests: the ORIGINAL FirmaEC
# library (firmadigital-libreria) + oracle/Oracle.java. Requires git, JDK 17+ and Maven.
#
#   FIRMAEC_JAVA_SRC=/path/to/firmadigital-libreria  (optional, otherwise it is cloned)
#   FIRMAEC_JAVA_REF=014b32719ad9d0ead566e9b007ceffbdefcbe0e0  (commit the port is based on)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ORACLE="$ROOT/oracle"
REF="${FIRMAEC_JAVA_REF:-014b32719ad9d0ead566e9b007ceffbdefcbe0e0}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SRC="${FIRMAEC_JAVA_SRC:-}"
if [ -z "$SRC" ]; then
  SRC="$WORK/firmadigital-libreria"
  git clone -q https://minka.gob.ec/mintel/ge/firmaec/firmadigital-libreria.git "$SRC"
  git -C "$SRC" checkout -q "$REF"
fi
echo "Compilando la librería Java original ($(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo local))..."
(cd "$SRC" && mvn -q -DskipTests package dependency:copy-dependencies)

rm -rf "$ORACLE/lib" "$ORACLE/lib-extra" "$ORACLE/classes"
mkdir -p "$ORACLE/lib" "$ORACLE/lib-extra" "$ORACLE/classes"
cp "$SRC"/target/libreria-*-SNAPSHOT.jar "$ORACLE/lib/"
rm -f "$ORACLE"/lib/*-sources.jar
cp "$SRC"/target/dependency/*.jar "$ORACLE/lib/"

# DSS full validation (used only by the oracle's verify-xml) needs the policy module
cat > "$WORK/pom.xml" <<'POM'
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>x</groupId><artifactId>x</artifactId><version>1</version>
<dependencies><dependency><groupId>eu.europa.ec.joinup.sd-dss</groupId><artifactId>dss-policy-jaxb</artifactId><version>6.3</version></dependency></dependencies></project>
POM
mvn -q -f "$WORK/pom.xml" dependency:copy-dependencies -DoutputDirectory="$WORK/extra"
for j in "$WORK"/extra/*.jar; do
  stem="$(basename "$j" | sed -E 's/-[0-9][^-]*\.jar$//')"
  ls "$ORACLE/lib" | grep -q "^$stem-[0-9]" || cp "$j" "$ORACLE/lib-extra/"
done

javac -cp "$ORACLE/lib/*:$ORACLE/lib-extra/*" -d "$ORACLE/classes" "$ORACLE/Oracle.java"
echo "Oráculo listo: $ORACLE"
