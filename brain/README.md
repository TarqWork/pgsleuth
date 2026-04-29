# pgsleuth-brain

The LLM-powered diagnostic brain for pgsleuth.

Consumes structured findings from the agent (over OTLP / JSON), reasons over them with a configurable LLM (local Ollama default, frontier models opt-in), and emits human-readable explanations and remediation suggestions.

**The brain never connects to the database.** The agent is the only component with database access; the brain is pure reasoning over findings.

## Status

Pre-alpha. First implementation lands phase 2 (week 7).
