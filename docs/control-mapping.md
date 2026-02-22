# Control Mapping (Security-First)

## OWASP LLM Top 10 (2025)

- LLM01 Prompt Injection:
  - `PromptInjectionAttack` demonstrations
  - `DefensePipeline` + `ContextAwareFilter` mitigation path
- LLM02 Sensitive Information Disclosure:
  - `ContentRedactor` for common PII/secret patterns
- LLM05 Supply Chain Vulnerabilities:
  - CI dependency auditing and SBOM generation
- LLM07 Insecure Plugin Design / Tool Use:
  - Context/session isolation model and integrity checks
- LLM09 Overreliance:
  - Uncertainty scorer + human-review requirement signal

## NIST AI RMF + GenAI Profile Alignment

- Govern:
  - Security policy, disclosure process, contribution controls.
- Map:
  - Documented threat model and trust boundaries.
- Measure:
  - Eval corpus, pass rates, review-required rates.
- Manage:
  - CI security checks, release hardening, patch workflows.
