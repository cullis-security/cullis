# OPA Policy — Enterprise B (ChipFactory)
#
# Controls which sessions the supplier agent can accept via ATN.
# The ATN broker calls POST /v1/data/atn/session/allow with the session request.
#
# Rules:
#   - Only accept sessions from approved buyer organizations
#   - Only allow specific capabilities
#   - Block specific agents if needed

package atn.session

import rego.v1

default allow := false

allow if {
    is_allowed_org
    has_required_capabilities
    not is_blocked_agent
}

is_allowed_org if {
    data.config.allowed_initiator_orgs[input.initiator_org_id]
}

is_allowed_org if {
    input.initiator_org_id == input.target_org_id
}

has_required_capabilities if {
    required := {cap | cap := input.capabilities[_]}
    allowed := {cap | cap := data.config.allowed_capabilities[_]}
    count(required - allowed) == 0
}

is_blocked_agent if {
    data.config.blocked_agents[input.target_agent_id]
}

is_blocked_agent if {
    data.config.blocked_agents[input.initiator_agent_id]
}
