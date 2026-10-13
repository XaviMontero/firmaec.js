#!/bin/bash
# Runs the Java FirmaEC oracle (original library) — see Oracle.java and scripts/setup-oracle.sh
DIR="$(cd "$(dirname "$0")" && pwd)"
JAVA="${ORACLE_JAVA:-${JAVA_HOME:+$JAVA_HOME/bin/}java}"
exec "$JAVA" -cp "$DIR/classes:$DIR/lib/*:$DIR/lib-extra/*" Oracle "$@" 2>/dev/null
