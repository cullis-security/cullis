# OPA Policy — Enterprise A (ElectroStore)
#
# Controls which sessions the buyer agent can open via ATN.
# The ATN broker calls POST /v1/data/atn/session/allow with the session request.
#
# Rules:
#   - Only allow sessions with approved supplier organizations
#   - Only allow specific capabilities (order.read, order.write)
#   - Block specific agents if needed (e.g. compromised agent IDs)

package atn.session

import rego.v1

default allow := false

# Allow if all conditions are met
allow if {
    is_allowed_org
    has_required_capabilities
    not is_blocked_agent
}

# Only allow sessions with approved supplier orgs
is_allowed_org if {
    data.config.allowed_target_orgs[input.target_org_id]
}

# Initiator's own org is always allowed (intra-org)
is_allowed_org if {
    input.initiator_org_id == input.target_org_id
}

# All requested capabilities must be in the approved list
has_required_capabilities if {
    required := {cap | cap := input.capabilities[_]}
    allowed := {cap | cap := data.config.allowed_capabilities[_]}
    count(required - allowed) == 0
}

# Check blocked agents list
is_blocked_agent if {
    data.config.blocked_agents[input.target_agent_id]
}

is_blocked_agent if {
    data.config.blocked_agents[input.initiator_agent_id]
}
