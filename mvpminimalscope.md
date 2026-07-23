# MVP — Minimal Build Scope

**Goal:** the smallest thing that proves the architecture — one governed, evidence-backed answer to *"Can CVE-X on app-Y reach sensitive data, and how do we fix it?"*, read-only, end-to-end. Because the MVP performs **no enterprise writes**, the approval/notification machinery drops out entirely — the single biggest simplifier.

## 1. Minimal service set (10 deployables + 1 library)

| # | Component | MVP-minimal form |
|---|---|---|
| 1 | chat-api | Entra token validation · streaming endpoint · SSE via Redis · status. |
| 2 | context-api | Entra → signed 5-min context token · sessions/conversations in Postgres. No memory facts. |
| 3 | orchestrator | **Rule-based intent** (one intent — no LLM needed) · route or decline. |
| 4 | registry adapter | Read-through client on Enterprise Agent Registry, (id,version) pinning, APPROVED check, fail closed. Library if the registry API is stable. |
| 5 | policy-api | One static policy bundle: allow workflow + 8 read tools; constraints (read_only, depth≤4, pii masked, budgets); deny everything else. |
| 6 | workflow-runtime + Temporal | One workflow, cancel signal only, quality-loop bound = 2. |
| 7 | agent-runtime | Skill execution, I/O schema validation, budget hard-stop. Mode 1 only. |
| 8 | LLM shim (library) | Prompt-ref resolution · per-execution budgets (Redis) · cost events. |
| 9 | tool-gateway | Schema validation · policy check · **templated-query guards** (§3) · masking · audit emit. |
| 10 | cyber-domain-api | 8 read endpoints over Neo4j RO + data products + object store. |
| 11 | verification-response | 4 checks (evidence_resolution, chain_path_validity, risk_explanation, redaction), no egress, ≤2 repair iterations. |

**Invariants that survive minimalization untouched:** single egress (NetworkPolicies from day 1 — 3 namespaces: edge/core/egress) · fail closed · LLM never writes · signed context token on every hop · every claim carries a resolvable ev:// ref · every call emits an audit event. Cut features, never these.

## 2. Minimal registry content

- **1 agent** — `vulnerability_chaining_agent@1`
- **1 workflow** — `vulnerability_chaining_workflow@1` (baseline §5 steps 1–9; no park/write steps)
- **9 skills + 1 deterministic scorer** — entity_resolution · finding_retrieval · cve_enrichment · asset_app_mapping · exposure_context · graph_path_query · data_impact · remediation_recommendation (runbook-lookup stub) · evidence_packaging · chain_risk_scorer@1
- **8 read tools** — graph_query (templated) · vulnerability_findings · cve_enrichment · asset_inventory · application_ownership · network_exposure · data_classification · evidence_store
- **Governance artifacts** — 1 policy bundle · 1 output contract (`vuln_chain_response@1`) · ~8 prompt refs · 1 eval set (25–30 golden questions, gates APPROVED)

## 3. Minimal guard posture — templates before AST

MVP ships **templated queries, not NL2Query**: graph_path_query uses a registry-stored parameterized Cypher template — the LLM supplies only parameter values (start nodes, target labels), never query text. Gateway validates parameters against the tool schema, clamps depth, injects the tenant predicate, masks per obligations. Security properties of guards g2–g5/g7–g8 at ~10% of the build; the full AST chain arrives with NL2Query without changing the tool contract.

## 4. Minimal infrastructure

OpenShift: 3 namespaces (edge/core/egress) with top-down NetworkPolicies · Postgres HA (context, policy, workflow_meta + Temporal history) · Neo4j RO (topology only — no knowledge edges yet) · Redis (SSE, budgets, idempotency) · Kafka **2 topics** (audit.events.v1, tool.calls.v1 → object-storage sink) · object storage (evidence + audit archive, write-once) · Enterprise: Entra ID, LLM Gateway (via shim), Agent Registry, Observability (OTel).

## 5. Explicitly deferred (each with a seam that makes it additive)

Approvals/notification (no writes exist) · Jira path · Graph RAG ingestion & knowledge edges (runbook stub; seam = knowledge_retrieval tool contract) · NL2Query + semantic models + AST guard chain (seam = same tool contract) · hybrid retrieval · memory facts · CyberShim (seam = 3 tool registrations) · second agent & composition (seam = registry bundles) · mode-2 loops / LangGraph / Agent SDK (seam = agent-runtime invocation contract) · OpenSearch · MCP facade · Entra Agent ID delegation chains · A2A.

## 6. Definition of done (demo runs twice unattended)

1. Entra sign-in → the CVE question → streamed progress → grounded answer with risk score, chain paths, remediation — every claim carrying a resolvable ev:// ref.
2. Other-tenant / unentitled user → filtered or declined — tenant-boundary test green.
3. "Patch the server" → declined by orchestrator, denied by policy, denial audited.
4. Pod killed mid-run → Temporal resumes, answer arrives, no duplicate tool calls.
5. Depth-6 request → clamped to 4, clamp visible in tool.calls audit.
6. Seeded verification FAIL → one repair iteration → PASS or user-safe failure.
7. Eval set ≥ threshold, registry APPROVED, any answer reconstructable via workflow_execution_id join.
