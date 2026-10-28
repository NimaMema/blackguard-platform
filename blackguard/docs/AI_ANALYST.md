# Private AI analyst (optional)

Core monitoring never depends on AI. The analyst is **disabled** unless `BLACKGUARD_OLLAMA_URL` is set.

## Enable it

```bash
# on the BLACKGUARD server
ollama pull llama3.1:8b          # or any local model that handles JSON output well
BLACKGUARD_OLLAMA_URL=http://127.0.0.1:11434 BLACKGUARD_OLLAMA_MODEL=llama3.1:8b python3 start.py
```

A non-loopback Ollama URL is refused unless `BLACKGUARD_ALLOW_REMOTE_OLLAMA=1` is also set. Paid or cloud APIs are not supported, by design.

## How it works (implemented in `guard/ai.py`)

1. An analyst or admin clicks **Ask the AI analyst** in an incident's workspace. Requests are rate-limited to 4/min per user and audited.
2. BLACKGUARD builds a bounded prompt: incident metadata, the rule description and its known false positives, and up to 60 evidence events with secrets redacted.
3. The system prompt requires the model to use only the provided evidence, cite event IDs, state uncertainty and benign explanations, and never suggest attacks or security-changing shell commands.
4. The response must be JSON. BLACKGUARD **validates every cited event ID** against the incident's evidence, flags invalid citations as possible hallucination, and flags summaries with no valid citation as unsupported.
5. The result is stored as an incident note of kind `ai`, labelled *unverified*, with the model name.

## Guarantees

- The model has **no tools**. It cannot run commands, change rules, approve responses or modify data. Its text is shown to a human, and that is all.
- Evidence never leaves the machine (with the default loopback URL).
- Turning the analyst off removes nothing else from the platform.

## Future work

- Streaming responses and a per-incident Q&A thread.
- A larger evidence context through summarisation tiers.
- An evaluation harness against the realistic datasets, so model quality can be measured before trusting it.
