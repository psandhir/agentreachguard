# Threat model

HorusTrace focuses on security consequences of effective agent authority across configuration, tools, identity, resources and data flow.

## In scope

- unsafe approval/guardrail configuration;
- overly broad or destructive agent capabilities;
- excessive declared/effective authority relative to a capability budget;
- broad IAM roles, wildcard permissions and OAuth scopes;
- static credential-source risks;
- insecure MCP transport/authentication/package configuration;
- broad filesystem/resource scopes;
- unrestricted or undeclared outbound destinations;
- sensitive-data-to-egress combinations;
- attack paths from untrusted input to privileged action;
- attack paths combining sensitive data, arbitrary execution, secret access and outbound capability;
- Google ADK-specific execution, toolset, MCP, A2A and delegated-agent control surfaces.

## Trust boundaries

Typical boundaries represented in the model are:

- user vs external/untrusted content;
- model/agent vs privileged tool;
- agent identity vs cloud resource;
- trusted data source vs external network destination;
- local application vs remote MCP server.

## Out of scope for v0.1

HorusTrace does not claim to:

- execute or dynamically test an agent;
- prove prompt-injection exploitability from arbitrary natural language;
- emulate a cloud provider's full IAM authorization engine;
- resolve all inherited/group-based permissions from live control planes;
- detect malware inside an MCP implementation;
- replace secret scanners, SAST, dependency scanners or runtime DLP;
- provide formal interprocedural taint analysis of arbitrary application code.

These boundaries are deliberate: findings should remain explainable and suitable for deterministic CI gates.


## ADK-specific trust boundaries

ADK adds trust boundaries between parent and delegated agents, local/sandboxed execution environments, remote MCP servers, remote A2A agents, Google API credentials/scopes, and retrieved external content. HorusTrace represents these as normalized capabilities and edges rather than assuming that a child agent or toolset inherits the parent security posture safely.
