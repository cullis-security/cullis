# Insurance demo — multi-surface cross-org A2A

Three-surface demo (Cullis Chat consumer / Frontdesk enterprise / Mastio
admin dashboard) showing 5 principals exchanging messages across two orgs.
Insurance claims escalation scenario.

## Cast

Two orgs. Display name (the brand the user sees) lives separately from
the backend ``org_id`` so we can reuse the reference stack without
re-bootstrapping with new IDs:

  Display name              Backend org_id    Trust domain
  ─────────────────────────────────────────────────────────
  Mediterranean Insurance   orga              orga.test
  Asia-Pacific Insurance    orgb              orgb.test

Principal IDs in audit logs and on the wire use the backend ``org_id``
(``orga::user::claim-officer``). The dashboard maps ``orga`` →
"Mediterranean Insurance" at the display layer.

Plus ``court`` as federation hub.

Personas (the humans behind the user principals — Mediterranean side
Italian, Asia-Pacific side Japanese; mirrors the realistic insurance
scenario where a Roma–Napoli accident involves a Japanese-insured
counterparty, see claim INC-2026-0501 in `seed/claims.sql`):

  - `claim-officer`         → Marco Conti       (Italian, junior)
  - `claim-manager`         → Lucia Bianchi     (Italian, senior)
  - `counterparty-liaison`  → Kenji Watanabe    (Japanese, partner)

Bots have no human face — they are just `Night Reporter` and `Ticket Bot`.

Five principals + 1 workload + 1 resource:

| Backend ID | Type | Surface |
|---|---|---|
| `orga::user::claim-officer` | user | Cullis Chat (single-user desktop) |
| `orga::user::claim-manager` | user | Cullis Chat dashboard `/chat` |
| `orga::agent::night-reporter` | agent | none (cron-style script) |
| `orga::agent::ticket-bot` | agent | none (request-response script) |
| `orgb::user::counterparty-liaison` | user | Frontdesk (multi-user web) |
| `orgb::workload::frontdesk-container` | workload | n/a (visible in admin) |
| `orga::resource::mcp::claims-db` | resource | postgres MCP server |

Full UI/SPA contract: `imp/insurance-demo-spec.md`

## Workflow

1. Overnight: `night-reporter` (agent) queries `claims-db` for cross-company-flagged
   cases, sends summary to `claim-officer` inbox. **A2U intra-org.**
2. Morning: `claim-officer` (user, Cullis Chat) reads, picks the most urgent,
   escalates to `claim-manager`. **U2U intra-org.**
3. `claim-manager` (user, Cullis Chat /chat) decides cross-company action,
   asks `ticket-bot` to generate a formal ticket. **U2A intra-org.**
4. `ticket-bot` returns ticket ID. **A2U intra-org return.**
5. `claim-manager` sends request to `counterparty-liaison` at Asia-Pacific,
   referencing ticket. **U2U cross-org.**
6. `counterparty-liaison` (user, Frontdesk) receives in inbox, reads, replies.

Quadrants ADR-020 covered: A2U, U2U intra, U2A, U2U cross-org. Missing: A2A
(intentional — demo clarity over completeness).

## Files

  README.md            this file
  seed/
    seed.py            provision the 5 principals + 1 workload + claims-db
    claims.sql         insurance claims fixture (cross-company flag, urgency,
                       region, etc.) seeded into the postgres MCP server
  bots/
    night_reporter.py  agent script — overnight scheduled run
    ticket_bot.py      agent script — request-response loop
  compose.frontdesk.yml  overlay adding Frontdesk container to reference
  run.sh               orchestration — bring up reference + frontdesk overlay,
                       run seeds, optional manual triggers

## Running the demo

  cd reference
  ./demo.sh full                                  # base reference up
  cd scenarios/insurance-demo
  ./run.sh seed                                   # provision principals + claims
  ./run.sh frontdesk                              # bring up Asia-Pacific Frontdesk
  ./run.sh trigger-night-reporter                 # manual A2U trigger
  ./run.sh urls                                   # print recording-ready URLs

Then browser:
  Cullis Chat (claim-officer):   http://localhost:9100/chat
  Cullis Chat (claim-manager):   http://localhost:9100/chat?user=manager  (or alt port)
  Asia-Pacific Frontdesk:               http://localhost:8090?user=liaison
  Mediterranean Mastio admin:             http://localhost:9100/admin
  Asia-Pacific Mastio admin:            http://localhost:9200/admin

## Cleanup

  ./run.sh down                                   # tears down frontdesk overlay
  cd ../.. && ./demo.sh down                      # tears down reference

## Anthropic API key

  export ANTHROPIC_API_KEY=$(grep ^ANTHROPIC_API_KEY \
    ../../../imp/official_sandbox/.env | cut -d= -f2-)

  ./run.sh seed   # picks it up from env, configures litellm_embedded
                  # on Mediterranean proxy AI gateway

The bots use Haiku 4.5 for cost; Cullis Chat user-facing path uses whatever
the user's session config has set.
