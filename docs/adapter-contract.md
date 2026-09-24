# HorusTrace framework adapter contract v1

HorusTrace v0.5 defines a small public contract between framework-specific source
parsers and the framework-neutral security model.

A Python framework adapter consists of:

- a stable lowercase kebab-case `name`;
- a `detector(Path) -> bool` that decides whether a source file uses the framework;
- a `scanner(Path) -> Graph` that statically normalizes supported constructs;
- `contract_version = 1`.

The target application must never be imported or executed by an adapter. Adapters
inspect source/configuration and return `horustrace.models.Graph` entities for the
core scanner to consolidate, enrich, and project into the Agent Security Graph.

## Normalized output

Adapters should emit only evidence they can support statically. Relevant normalized
entities include:

- `Agent`
- `Tool`
- `MCPServer`
- `Identity`
- `DataSource`
- `InputSource`
- `NetworkDestination`
- `AgentPolicy`
- coverage diagnostics for material unresolved constructs

Framework-specific facts that do not yet have a first-class field belong in
`metadata`, with source locations retained wherever possible. Core security
semantics such as effective authority, attack paths, source-context classification,
and policy evaluation should not be reimplemented inside framework adapters.

## Safety rules

An adapter must not:

- import the target repository;
- execute target Python;
- launch an agent or MCP server;
- fetch remote MCP metadata;
- authenticate to cloud/SaaS services;
- infer runtime effectiveness from configuration presence.

Dynamic or unsupported constructs should be represented as unresolved coverage rather
than guessed.

## Inspecting the installed contract

```bash
horustrace adapters
horustrace adapters --format json
```

The catalogue reports the adapter contract version and execution model for every
built-in Python adapter.

## Adding framework support

A built-in adapter should implement `is_<framework>_file(path)` and
`scan_python_file(path)`, then be registered in
`horustrace.adapters.registry.PYTHON_FRAMEWORK_ADAPTERS` using
`PythonFrameworkAdapter`.

New adapters should include:

1. positive and negative detector fixtures;
2. normalization tests for agents/tools/MCP/identity/control semantics;
3. dynamic/unresolved coverage tests;
4. at least one real-world public-repository regression shape;
5. no-target-execution/adversarial checks where applicable.

Automatic loading of arbitrary installed third-party plugins is intentionally not part
of contract v1. That keeps CLI execution deterministic and avoids expanding the trust
boundary merely by installing a Python package.
