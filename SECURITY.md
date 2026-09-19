# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue containing exploit details for a vulnerability in AgentReachGuard.

Use GitHub's **Report a vulnerability** / private security-advisory flow when it is enabled for this repository. If that option is temporarily unavailable, open a minimal public issue asking the maintainer for a private reporting channel **without including vulnerability details**.

Please include privately:

- affected version/commit;
- reproducible steps or proof of concept;
- impact;
- suggested mitigation if known.

## Scanner threat model

AgentReachGuard treats scanned repositories and configuration as untrusted input.

The static scanner must not:

- import scanned Python modules;
- execute shell commands from scanned code/configuration;
- launch MCP servers;
- resolve or fetch remote dependencies as part of ordinary scanning.

Parser denial-of-service, path traversal, unsafe deserialization, credential disclosure, or any behaviour that causes target code to execute should be treated as security-relevant defects.

## Hostile repository scanning guarantees

AgentReachGuard statically parses supported source and configuration files. It does not
import scanned Python modules, execute target code, launch subprocesses, start MCP
servers, or fetch dependencies. The adversarial fixture suite covers import and process
side effects, hostile MCP commands, malformed source, dynamic configuration, oversized
input limits, YAML alias limits, and symlink escapes. A coverage diagnostic means the
scanner did not fully analyze that construct; it does not mean the construct is safe.
