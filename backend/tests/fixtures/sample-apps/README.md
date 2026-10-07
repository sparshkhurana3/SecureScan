# Planted sample applications

Small applications with deliberately planted weaknesses. Every secret in them is fake. They are
inputs for the scanners in integration tests, contract tests and the regression suite.
Each application has an `expected-findings.yaml`: per tool, the rule ids or titles that must appear.
The lists start as skeletons and are filled in during M1 (spike S7) after the first real runs.

| App | Planted weaknesses |
| --- | --- |
| java-planted | SQL injection by string concatenation, hard-coded secret, vulnerable dependency (log4j-core 2.14.1) |
| js-planted | `eval` on request input, command injection, hard-coded token, vulnerable dependency (lodash 4.17.15) |
| python-planted | shell injection, `pickle.loads` on request data, hard-coded secret, vulnerable dependency (flask 0.12) |
| csharp-planted | string-built SQL, hard-coded connection string (source only, no build output) |

`java-planted/target/java-planted.jar` is built by `scripts/build_planted_jar.sh` (Maven in a container)
and committed, so SpotBugs can run without a build.
