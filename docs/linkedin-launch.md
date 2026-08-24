# LinkedIn Launch Announcement

I’m releasing **EvidenceVeil**, a new open-source cybersecurity privacy-engineering tool built around a problem I keep seeing in incident response: we often need to share the evidence, but we should not have to expose the entire incident to do it.

Security telemetry can contain far more than obvious PII. User identities, credentials, internal hostnames, network topology, cloud account identifiers, case references, exact timelines, customer context, and rare behaviors can all create disclosure or re-identification risk. At the same time, simple find-and-replace redaction can destroy the relationships investigators and detection engineers actually need.

EvidenceVeil is designed to address both sides of that problem.

It runs locally and offline by default. Policies can redact, generalize, synthesize, tokenize, or pseudonymize sensitive values while preserving explicitly selected relationships such as repeated users, hosts, sessions, event order, timestamp deltas, and format-compatible infrastructure identifiers. When reversibility is needed, the mapping is kept in a separately encrypted vault rather than inside the shareable package.

The v1.0 release also includes residual-risk auditing, utility contracts, manifests and checksums, a self-contained offline HTML report, archive-safety primitives, synthetic test fixtures, a fixture-safety GitHub Action with SARIF output, and a plugin SDK.

One design principle matters most: **EvidenceVeil never claims that replacing identifiers automatically makes data anonymous or legally safe to disclose.** Pseudonymized data may still be personal data, and release decisions still require human review of purpose, recipients, auxiliary information, law, and organizational controls.

Open source, Apache-2.0, and built to be genuinely useful without a SaaS account, API key, or LLM.

GitHub: https://github.com/MrTaherAmine/evidenceveil
Website: https://www.taheramine.org

I’d especially value feedback from DFIR teams, SOCs, privacy engineers, detection engineers, researchers, MSSPs, and anyone who has had to answer the question: “How do we share enough evidence to be useful without sharing everything?”

#CyberSecurity #DFIR #PrivacyEngineering #IncidentResponse #OpenSource #SecurityEngineering
