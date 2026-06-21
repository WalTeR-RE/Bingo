"""
Intent Router — classifies user speech into actionable intents.

Uses OpenAI **Structured Outputs** (response_format) to guarantee the
LLM response always matches the IntentResult Pydantic schema — no
manual JSON parsing, no format mismatches, no silent failures.
"""

import logging
from typing import Optional

from openai import OpenAI
from pydantic import BaseModel, ValidationError

from .contracts import IntentCategory, IntentResult

logger = logging.getLogger("bingo.router")

class _OffensiveParams(BaseModel):
    url: str = ""
    username: Optional[str] = None
    password: Optional[str] = None
    cookies: Optional[dict[str, str]] = None
    vuln_types: Optional[list[str]] = None
    security_level: Optional[str] = None
    scan_level: Optional[int] = None

class _DefensiveStartParams(BaseModel):
    mode: str = "sniffer"
    upstream_host: Optional[str] = None
    upstream_port: Optional[int] = None
    loopback: bool = False
    port: Optional[int] = None

class _RouterResponse(BaseModel):
    """Schema the LLM MUST produce — enforced by OpenAI Structured Outputs."""
    intent: IntentCategory
    offensive_params: Optional[_OffensiveParams] = None
    defensive_start_params: Optional[_DefensiveStartParams] = None

ROUTER_SYSTEM_PROMPT = """You are a command router for Bingo, an autonomous AI security engineer.
Classify the user's spoken request into exactly one intent category and extract relevant parameters.

INTENT CATEGORIES:
- "offensive" — scan, test, pentest, exploit, or attack a target. Fill offensive_params.
  vuln_types can include: sqli, xss, lfi, rfi, ssrf, csrf, command_injection, file_upload, brute_force, ssti, xxe, idor, open_redirect.
  scan_level: 1 = fast/quick scan, 2 = deep/thorough (default), 3 = ultimate/exhaustive (very long).
  Map "fast"/"quick"→1, "deep"/"thorough"/"normal"→2, "ultimate"/"exhaustive"/"full"/"deepest"→3.
- "defensive_start" — start network monitoring, enable the WAF. Fill defensive_start_params.
  Default mode is "sniffer" (passively monitors ALL of the device's network traffic).
  Only set mode="proxy" if the user explicitly asks to put the WAF in front of one app/port.
  If the user wants to monitor localhost / 127.0.0.1 / a local app (e.g. "watch localhost",
  "monitor the local DVWA", "capture loopback"), set loopback=true. If they mention a port,
  put it in "port" (e.g. "localhost 4280" → loopback=true, port=4280).
- "defensive_stop" — stop monitoring / turn off WAF.
- "defensive_status" — get WAF status, stats, or threat count.
- "scan_status" — status of an ongoing or recent scan.
- "conversation" — general chat, questions, greetings.

RULES:
- If the user mentions a URL, IP, or hostname, extract it fully including port if mentioned.
  IMPORTANT: Speech-to-text often converts port numbers to words. Interpret carefully:
  - "port 4280" or "port four two eight zero" → :4280
  - "on port 80" or "on board 80" or "on port eighty" → :80
  - "localhost 4280" or "localhost on 4280" → http://localhost:4280
  - "on board" likely means "on port" (speech recognition artifact)
  The URL must include the port as :<port> when mentioned (e.g. http://localhost:4280).
- Add http:// if no protocol is specified.
- If the user mentions credentials, extract them.
- If ambiguous, prefer "conversation".
- Only fill the params object that matches the intent; leave the other null."""

class IntentRouter:
    """Classifies user speech into structured intents using OpenAI Structured Outputs."""

    def __init__(self, openai_client: OpenAI, model: str = "gpt-4o-mini"):
        self._client = openai_client
        self._model = model

    def classify(self, user_text: str) -> IntentResult:
        """
        Classify user text into a validated IntentResult.

        OpenAI Structured Outputs guarantees the response matches
        _RouterResponse — then we convert to IntentResult (the
        contract model used by the dispatcher).

        Returns IntentResult. Falls back to conversation on error.
        """
        fallback = IntentResult(intent=IntentCategory.CONVERSATION)

        try:
            response = self._client.beta.chat.completions.parse(
                model=self._model,
                messages=[
                    {"role": "system", "content": ROUTER_SYSTEM_PROMPT},
                    {"role": "user", "content": user_text},
                ],
                response_format=_RouterResponse,
                max_tokens=200,
                temperature=0.0,
            )

            parsed: _RouterResponse = response.choices[0].message.parsed

            if parsed is None:
                logger.warning("Router returned None (possible refusal)")
                return fallback

            params = {}
            if parsed.intent == IntentCategory.OFFENSIVE and parsed.offensive_params:
                params = parsed.offensive_params.model_dump(exclude_none=True)
            elif parsed.intent == IntentCategory.DEFENSIVE_START and parsed.defensive_start_params:
                params = parsed.defensive_start_params.model_dump(exclude_none=True)

            result = IntentResult(intent=parsed.intent, params=params)
            logger.info("Intent: %s | Params: %s", result.intent.value, result.params)
            return result

        except ValidationError as e:
            logger.warning("Router validation error: %s", e)
            return fallback
        except Exception as e:
            logger.error("Router error: %s", e)
            return fallback
