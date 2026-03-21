# Project Status

## Current Release Line: 0.2.x

The current release line is intended to be publicly shareable and reproducible for security engineers.

Completed in this line:

- Modular web stack in `src/web`
- Service-layer defense pipeline and canonicalization flow
- CLI workflows for `scan`, `eval`, and `serve`
- Packaged baseline evaluation dataset for installed CLI use
- Governance, release, and supply-chain documentation

## Stable Public Surface for This Release

- Web demo launched through `app.py`
- CLI entrypoints exposed through `src.cli`
- Baseline evaluation workflow and dataset schema
- Structured security event outputs from the service layer

## Future Work

These are possible future extensions, not release commitments:

### Core Lab & Telemetry
- Expand the eval corpus with labeled false-positive and false-negative cases
- Add policy packs for more agentic workflow scenarios
- Add structured telemetry export sinks
- Add release provenance and signature attestations beyond the current SBOM flow

### Advanced Attack Vectors
- **Multi-Turn Jailbreaks**: Simulate conditioning an LLM over several messages to bypass alignment filters over time.
- **Data Exfiltration Architectures**: Showcase how hijacked models securely exfiltrate data (e.g., Markdown image rendering exfiltration).
- **"Many-Shot" Evasion**: Demonstrate context-window stuffing with hundreds of fake benign Q&A pairs.
- **RAG Poisoning**: Introduce attack scenarios for Retrieval-Augmented Generation where external documents are poisoned.

### Enhanced Defense Mechanisms
- **Constitutional / Self-Correction Loop**: Implement an asynchronous reviewer/Judge LLM to evaluate the primary model's output before surfacing it.
- **Perplexity & Entropy Scoring**: Add a scanner to filter highly anomalous payloads (like heavy Leetspeak or Zalgo text) before they reach the model.
- **LLM-as-a-Judge Evaluation**: Upgrade the `eval` suite to use an LLM API to score mitigation success rather than relying solely on heuristics.

### Real-World Integration & Infrastructure
- **Live Model Backend (Optional)**: Add an optional backend to plug into local inferencing engines (e.g., `Ollama`, `vLLM`) to test attacks against real models.
- **GitHub Action / CI Scanner**: Build an automated runner for `adml scan` to act as an automated PR reviewer for prompt injections and risky system prompts.
- **Red Teaming Auto-Fuzzer**: Add an `adml fuzz` command to automatically iterate through evasion and injection techniques against target endpoints.
