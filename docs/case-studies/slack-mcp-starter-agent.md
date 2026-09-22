# Case study: Slack MCP starter agent

This case study uses the OpenAI Agents SDK implementation in
[slack-samples/bolt-python-starter-agent](https://github.com/slack-samples/bolt-python-starter-agent)
to demonstrate how HorusTrace can turn an agent repository into a security-policy
review.

The baseline public-corpus scan used commit
`11c0c31345a8a6088d8f26cb928a6423bb39e081`.

## Security question

The starter agent connects to Slack's remote MCP endpoint using the authenticated
user's bearer token. The prompt describes both read and write capabilities, including
message sending and Canvas modification.

For an enterprise knowledge assistant, a safer default is:

- treat Slack messages and retrieved workspace content as untrusted input;
- treat workspace content as confidential;
- permit network access only to the approved Slack MCP endpoint;
- expose only the Slack search/read tools required for the use case;
- deny shell execution, destructive writes, secrets access and identity administration;
- keep mutating Slack actions outside the default MCP tool surface;
- use least-privilege user OAuth scopes for the exposed tools.

The local emoji-reaction function is treated as an explicitly accepted low-impact
interaction in this example rather than as general Slack write authority.

## Baseline architecture

The relevant application pattern is:

```text
Slack user input
      |
      v
OpenAI Starter Agent
      |
      +-- local add_emoji_reaction tool
      |
      +-- runtime agent.clone(...)
              |
              v
       Slack remote MCP
       https://mcp.slack.com/mcp
              |
              +-- search/read tools
              +-- message write tools
              +-- Canvas write tools
              +-- other tools exposed by the server/token
```

The MCP connection is authenticated and uses HTTPS, which are positive controls.
However, the source does not apply an explicit MCP tool allowlist.

## Baseline HorusTrace result

The v0.4.1 public-corpus run reported:

```text
Agents:               1
Tools:                2
MCP servers:          1
Identities:           0
Coverage incomplete:  false
Findings:             1
```

The finding was:

```text
AGT032  medium  Remote MCP lacks an explicit tool allowlist
evidence:
  url=https://mcp.slack.com/mcp
  allowed_tools=none
```

This is not a claim that the Slack MCP server itself is insecure. The finding is
about the **agent-side authority boundary**: authentication controls who connects,
while an allowlist controls which server-provided actions the model can see and
invoke.

## Enterprise policy overlay

A representative HorusTrace policy for a read-oriented enterprise Slack assistant is:

```yaml
version: 1
agent:
  name: Starter Agent

  inputs:
    - name: slack_message
      trust: untrusted
      kind: external

  data:
    - name: slack_workspace_content
      classification: confidential
      capability: data.read
      selector: slack://workspace

  policy:
    denied_capabilities:
      - process.execute
      - destructive.write
      - secrets.read
      - identity.admin
      - external.write
      - data.write

    allowed_resources:
      - slack://workspace

    allowed_destinations:
      - https://mcp.slack.com/mcp

    max_privileged_capabilities: 1
```

The policy expresses business intent separately from source observations. It does not
pretend to configure Slack or the MCP server.

## Policy assessment of the baseline

### Compliant controls

- The MCP endpoint is fixed to `https://mcp.slack.com/mcp`.
- The connection uses an Authorization bearer header.
- No shell or local process-execution capability is present in the reviewed agent code.
- HorusTrace completed the static scan without coverage diagnostics.

### Security gaps

1. **Broad MCP discovery surface**

   No explicit tool filter is applied. The model can therefore be offered whatever
   tools the authenticated Slack MCP session exposes.

2. **Read/write authority is mixed**

   The application prompt advertises search/read capabilities alongside message and
   Canvas writes. A read-oriented enterprise assistant should not receive mutation
   authority by default.

3. **OAuth scope is not visible in the agent definition**

   HorusTrace can see that a bearer token is supplied, but it cannot currently prove
   the effective Slack scopes on that runtime token.

4. **Untrusted Slack content crosses the agent boundary**

   Slack channel, thread and search results are user-generated content and should be
   treated as untrusted input for prompt-injection purposes.

## Remediated design

For the read-oriented profile, restrict the MCP server at the client:

```python
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter

mcp_server = MCPServerStreamableHttp(
    params={
        "url": SLACK_MCP_URL,
        "headers": {"Authorization": f"Bearer {deps.user_token}"},
    },
    tool_filter=create_static_tool_filter(
        allowed_tool_names=[
            "slack_search_public",
            "slack_search_public_and_private",
            "slack_search_channels",
            "slack_search_users",
            "slack_read_channel",
            "slack_read_thread",
            "slack_read_user_profile",
        ]
    ),
)
```

The prompt should also describe the MCP connection as read-only and explicitly tell
the agent to treat Slack content as untrusted context rather than instructions.

If a separate workflow genuinely needs Slack write actions, expose only the required
write tools in a separate profile and apply explicit approval/guardrails rather than
mixing broad mutation authority into the default research assistant.

## Remediated architecture

```text
Slack message / retrieved content
           |
           | untrusted
           v
    Starter Agent
           |
           +-- approved low-risk local reaction tool
           |
           +-- runtime agent clone
                  |
                  v
            Slack MCP client
                  |
             static allowlist
                  |
        +---------+---------+
        |                   |
   search tools          read tools
        |                   |
        +---------+---------+
                  |
                  X
          write/admin tools
          not exposed
```

## Rescan result

With the OpenAI MCP normalization improvements introduced alongside this case study,
HorusTrace resolves the runtime clone attachment and the static MCP tool filter.

The local regression case produces:

```text
Coverage incomplete: false
MCP server bound to Starter Agent: yes
Remote MCP authenticated: yes
Explicit MCP allowlist: yes
Policy violations: 0
Findings: 0
```

The remediated ADG contains the agent, untrusted inputs, model, local tool, MCP server,
network destination, confidential Slack resource, and policy-control relationships.

## What this case demonstrates

This example is useful because the original code is not obviously "vulnerable" in
the traditional SAST sense. It uses HTTPS and an authenticated token.

The security problem is architectural:

```text
authenticated remote tool surface
        +
LLM tool autonomy
        +
read and mutation functions
        +
untrusted collaborative content
        =
agent authority that should be deliberately constrained
```

HorusTrace can make that authority boundary reviewable in CI rather than relying only
on a manual architecture review.

## Limits exposed by the case study

The exercise also identified two v0.4.1 normalization gaps:

- MCP servers attached through `agent.clone(mcp_servers=[...])` were discovered but
  not associated with the effective agent in the ADG.
- OpenAI Agents SDK `create_static_tool_filter(...)` configuration was not projected
  into `MCPServer.allowed_tools`.

The accompanying implementation addresses both patterns.

Further work is still needed to resolve live Slack OAuth scopes and to model the
security semantics of individual MCP tools beyond their configured allowlist.
