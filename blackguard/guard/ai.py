"""Optional private AI analyst backed by a local Ollama model.

Disabled unless BLACKGUARD_OLLAMA_URL is set. The model receives a bounded,
redacted copy of one incident's evidence and must answer in JSON citing event
IDs. BLACKGUARD validates citations, labels the output as model-generated and
unverified, and stores it as an incident note. The model has no tools and
cannot change anything; its suggestions are text for a human to evaluate.
"""

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from guard.security import redact

SYSTEM_PROMPT = """You are a cautious security analyst assistant for a home network monitoring tool.
You explain incidents to the network owner. Rules:
- Use ONLY the evidence provided. Never invent events, IPs, accounts or threat intelligence.
- Cite evidence by its numeric event id. Every claim must be supported by cited ids.
- State uncertainty plainly. Detection rules are heuristics; benign explanations are common.
- Suggest investigation steps a non-expert can perform with normal admin tools.
- Never suggest attacking, scanning or 'hacking back' anyone. Never output shell commands that change security settings.
Respond with a single JSON object with keys:
"summary" (string, <= 120 words), "cited_event_ids" (array of integers),
"benign_explanations" (array of strings), "uncertainties" (array of strings),
"suggested_steps" (array of strings), "confidence" ("low"|"medium"|"high")."""


class AIUnavailable(Exception):
    pass


class Analyst:
    def __init__(self, settings):
        self.url = settings.ollama_url.rstrip("/") if settings.ollama_url else ""
        self.model = settings.ollama_model

    @property
    def enabled(self):
        return bool(self.url)

    def status(self):
        return {"enabled": self.enabled, "model": self.model if self.enabled else None,
                "note": "Optional local model via Ollama. Output is advisory and unverified."}

    def build_prompt(self, detail, max_events=60):
        evidence = [{"id": e["id"], "time": e["timestamp"], "type": e["type"], "host": e["host"],
                     "source_ip": e["source_ip"], "account": e["actor"], "message": redact(e["message"])[:300],
                     "origin": f"{e['mode']}/{e['trust']}"} for e in detail["evidence"][:max_events]]
        payload = {
            "incident": {"title": detail["title"], "rule": detail["rule_id"], "rule_description": (detail.get("rule") or {}).get("description"),
                         "severity": detail["severity"], "rule_confidence": detail["confidence"],
                         "confidence_reasoning": detail["confidence_reason"], "summary": redact(detail["summary"]),
                         "status": detail["status"], "dataset": detail["mode"]},
            "evidence_total": len(detail["evidence"]), "evidence_shown": len(evidence), "evidence": evidence,
            "known_false_positives": (detail.get("rule") or {}).get("false_positives", []),
        }
        return json.dumps(payload, indent=1)

    def analyse(self, detail, timeout=120):
        if not self.enabled:
            raise AIUnavailable("The AI analyst is disabled. Set BLACKGUARD_OLLAMA_URL to a local Ollama server to enable it.")
        body = json.dumps({"model": self.model, "stream": False, "format": "json",
                           "options": {"temperature": 0.1},
                           "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                        {"role": "user", "content": self.build_prompt(detail)}]}).encode()
        request = Request(self.url + "/api/chat", data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=timeout) as response:  # nosec B310
                reply = json.loads(response.read(2_000_000))
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            raise AIUnavailable(f"Could not reach the local model at {self.url}: {exc}") from exc
        content = (reply.get("message") or {}).get("content", "")
        try:
            result = json.loads(content)
            if not isinstance(result, dict):
                raise ValueError
        except ValueError as exc:
            raise AIUnavailable("The model did not return valid JSON; try again or use a larger model.") from exc
        valid_ids = {e["id"] for e in detail["evidence"]}
        cited = [i for i in result.get("cited_event_ids", []) if isinstance(i, int)]

        def strings(key, limit=8):
            values = result.get(key) or []
            return [redact(str(v))[:400] for v in values if isinstance(v, (str, int, float))][:limit]

        analysis = {
            "summary": redact(str(result.get("summary", "")))[:1500],
            "cited_event_ids": [i for i in cited if i in valid_ids],
            "invalid_citations": [i for i in cited if i not in valid_ids],
            "benign_explanations": strings("benign_explanations"),
            "uncertainties": strings("uncertainties"),
            "suggested_steps": strings("suggested_steps"),
            "model_confidence": result.get("confidence") if result.get("confidence") in ("low", "medium", "high") else "unstated",
            "model": self.model,
        }
        if not analysis["cited_event_ids"]:
            analysis["uncertainties"].insert(0, "The model cited no valid evidence; treat this summary as unsupported.")
        if analysis["invalid_citations"]:
            analysis["uncertainties"].insert(0, f"The model cited event ids that are not part of this incident "
                                                f"({analysis['invalid_citations']}); it may be hallucinating.")
        return analysis

    @staticmethod
    def as_note(analysis):
        parts = ["AI analyst (local model, unverified — check against the evidence):", analysis["summary"]]
        for title, key in (("Possible benign explanations", "benign_explanations"), ("Uncertainties", "uncertainties"),
                           ("Suggested investigation steps", "suggested_steps")):
            if analysis[key]:
                parts.append(f"{title}:\n" + "\n".join(f"- {v}" for v in analysis[key]))
        parts.append(f"Cited evidence: {', '.join(f'#{i}' for i in analysis['cited_event_ids']) or 'none'}")
        return "\n\n".join(parts)
