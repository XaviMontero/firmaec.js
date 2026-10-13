#!/bin/bash
# Runs the Java FirmaEC oracle (original library) — see Oracle.java
DIR="$(cd "$(dirname "$0")" && pwd)"
JAVA="${ORACLE_JAVA:-$HOME/.sdkman/candidates/java/17.0.13-amzn/bin/java}"
exec "$JAVA" -cp "$DIR/classes:$DIR/lib/*:$DIR/lib-extra/*" Oracle "$@" 2>/dev/null
