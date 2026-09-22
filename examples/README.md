# HorusTrace examples

These examples demonstrate HorusTrace against intentionally secure and vulnerable
agent configurations.

- `secure-agent/` — framework-neutral secure example.
- `vulnerable-agent/` — framework-neutral example with findings to inspect.
- `google-adk-secure/` — secure Google ADK example.
- `google-adk-vulnerable/` — Google ADK example exercising security findings.

Run a scan from the repository root, for example:

```bash
horustrace scan examples/google-adk-secure --strict --fail-on high
```
