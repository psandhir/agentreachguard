"""Evidence origins and static control observations; neither proves runtime enforcement."""
from agentreachguard.adapters.google_adk import BUILTIN_TOOL_CAPABILITIES
from agentreachguard.models import EvidenceFact, Graph, SourceLocation

MANIFEST_NAMES = {'agentreachguard.manifest.yaml', 'agentreachguard.manifest.yml'}


def annotate(graph: Graph, path) -> None:
    declared = path.name in MANIFEST_NAMES
    location = SourceLocation(path)

    def facts(entity, subject, values, inferred=False, origin=None):
        origin = origin or ('declared' if declared else 'inferred' if inferred else 'observed')
        for value in values:
            fact = EvidenceFact(subject, value, origin, getattr(entity, 'location', None) or location)
            if fact not in entity.provenance:
                entity.provenance.append(fact)

    def tool_facts(tool):
        heuristic = tool.kind in {'function', 'adk_function', 'generic'} or (
            tool.kind in {'adk_builtin', 'adk_config_tool'}
            and (tool.metadata.get('adk_builtin') or tool.name) not in BUILTIN_TOOL_CAPABILITIES
        )
        facts(tool, tool.name, [f'capability={c}' for c in sorted(tool.capabilities)], heuristic,
              origin=tool.metadata.get('capability_origin'))
        facts(tool, tool.name, [f'approval_configuration={tool.approval}'])
        facts(tool, tool.name, [f'guardrail_hook_detected={tool.guardrails}'],
              inferred=bool(tool.metadata.get('guardrail_origin')))
        for resource in tool.resources:
            facts(resource, resource.selector,
                  [f'resource_selector={resource.selector}', f'classification={resource.classification}'])
        for destination in tool.destinations:
            # A literal URL in a function is evidence of a possible destination,
            # not an enforced network restriction.
            facts(destination, tool.name, [f'destination={destination.target}'], heuristic)

    for tool in graph.all_tools():
        tool_facts(tool)
    for server in graph.all_mcp_servers():
        facts(server, server.name, [f'transport={server.transport}',
                                   f'authentication_configuration={server.authenticated}',
                                   f'approval_configuration={server.approval}'])
    for identity in graph.all_identities():
        facts(identity, identity.name,
              [f'role={v}' for v in sorted(identity.roles)] +
              [f'permission={v}' for v in sorted(identity.permissions)] +
              [f'oauth_scope={v}' for v in sorted(identity.oauth_scopes)] +
              ([f'credential_source={identity.credential_source}'] if identity.credential_source else []))
    for agent in graph.agents:
        facts(agent, agent.name, ['agent_configuration_detected'])
        facts(agent, agent.name, [f'callback_hook={c}' for c in sorted(
            agent.metadata.get('callbacks') or {}
        )])
        if agent.metadata.get('safety_plugin'):
            facts(agent, agent.name, ['safety_plugin_name_detected'], inferred=True)
        for source in agent.data_sources:
            facts(source, source.name, [f'classification={source.classification}',
                                       f'capability={source.capability}'])
        for source in agent.inputs:
            facts(source, source.name, [f'input_trust={source.trust}', f'input_kind={source.kind}'],
                  bool(source.metadata.get('inferred')))
        for destination in agent.network:
            facts(destination, agent.name, [f'destination={destination.target}',
                                           f'restriction_declaration={destination.restricted}'])
        policy = agent.policy
        values = [f'required={c}' for c in sorted(policy.required_capabilities)]
        values += [f'denied={c}' for c in sorted(policy.denied_capabilities)]
        values += [f'approval_required_for={c}' for c in sorted(policy.require_approval_for)]
        values += [f'allowed_resource={v}' for v in policy.allowed_resources]
        values += [f'allowed_destination={v}' for v in policy.allowed_destinations]
        if policy.max_privileged_capabilities is not None:
            values.append(f'max_privileged_capabilities={policy.max_privileged_capabilities}')
        facts(policy, agent.name, values)


def context(agent):
    entities = [agent, agent.policy, *agent.tools, *agent.mcp_servers,
                *agent.identities, *agent.inputs, *agent.data_sources, *agent.network]
    for tool in agent.tools:
        entities.extend([*tool.resources, *tool.destinations])
    facts = []
    for entity in entities:
        for fact in entity.provenance:
            if fact not in facts:
                facts.append(fact)
    return facts


def attach_findings(graph, findings):
    by_name = {agent.name: agent for agent in graph.agents}
    for finding in findings:
        agent = by_name.get(finding.agent)
        if agent:
            if finding.layer in {1, 3}:
                entities = [*agent.tools, *agent.mcp_servers, *agent.identities]
                selected = [entity for entity in entities if entity.location == finding.location]
                finding.provenance = ([fact for entity in selected for fact in entity.provenance]
                                      if selected else list(agent.provenance))
            else:
                finding.provenance = context(agent)
        else:
            entities = [*graph.all_tools(), *graph.all_mcp_servers(), *graph.all_identities()]
            finding.provenance = [fact for entity in entities if entity.location == finding.location
                                  for fact in entity.provenance]
        if finding.rule_id.startswith('PATH') or finding.rule_id in {'AGT010', 'DATA003'}:
            finding.assessment = 'potential_risk'
            finding.limitations.append('Capability co-occurrence does not prove an executable data-flow path or exploitability.')
        elif finding.rule_id in {'CAP001', 'CAP002', 'CAP006', 'DATA002', 'NET003'}:
            finding.assessment = 'policy_violation'
        elif finding.rule_id == 'IDN001' or any(f.origin == 'inferred' for f in finding.provenance):
            finding.assessment = 'heuristic_risk'
        finding.limitations.append('Runtime authorization and control effectiveness are not verified by this static scan.')


def control_observations(graph):
    observations = []

    def add(subject, control, status, location):
        observations.append({'subject': subject, 'control': control, 'configuration': status,
                             'effectiveness': 'not_verified', 'location': (
                                 {'path': str(location.path), 'line': location.line} if location else None)})

    for agent in graph.agents:
        for callback in sorted(agent.metadata.get('callbacks') or {}):
            add(agent.name, callback, 'hook_detected', agent.location)
        if agent.metadata.get('safety_plugin'):
            add(agent.name, 'safety_plugin', 'name_inferred', agent.location)
    for tool in [*graph.all_tools(), *graph.all_mcp_servers()]:
        add(tool.name, 'approval', 'required' if tool.approval is True else
            'disabled' if tool.approval is False else 'unknown', tool.location)
        if tool.guardrails:
            add(tool.name, 'guardrail', 'boundary_or_hook_detected', tool.location)
        if tool.metadata.get('approval_hook_detected'):
            add(tool.name, 'approval_callback', 'hook_detected', tool.location)
        if tool.metadata.get('sandboxed') is not None:
            add(tool.name, 'sandbox', 'configured' if tool.metadata['sandboxed'] else
                'disabled', tool.location)
    for agent in graph.agents:
        for destination in agent.effective_destinations:
            add(agent.name, 'network_destination',
                'possible_destination_only' if destination.metadata.get('source') == 'literal_url'
                else 'restriction_configured' if destination.restricted else 'restriction_not_detected',
                destination.location)
    return observations
