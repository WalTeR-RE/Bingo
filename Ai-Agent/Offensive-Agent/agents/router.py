import json

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from ..models.schemas import RouterOutput
from ..prompts.templates import ROUTER_PROMPT
from ..utils.logger import get_logger

logger = get_logger("router_agent")


class RouterAgent:
    """Classifies which vulnerability types to test based on discovery results."""

    def __init__(self, config):
        self.config = config
        self.llm = ChatOpenAI(
            model=config.models.router,
            openai_api_key=config.openai_api_key,
            temperature=0,
            max_retries=10,
        )

    def run(self, discovery_output: str) -> RouterOutput:
        logger.info("Routing vulnerabilities")

        prompt = ROUTER_PROMPT.format(discovery_output=discovery_output)

        try:
            structured_llm = self.llm.with_structured_output(RouterOutput)
            result = structured_llm.invoke(
                [
                    SystemMessage(
                        content="You are a vulnerability classification router."
                    ),
                    HumanMessage(content=prompt),
                ]
            )
            logger.info(f"Router selected: {result.vuln_types}")
            return result
        except Exception as e:
            logger.warning(f"Structured router failed, using fallback: {e}")
            return self._fallback_run(discovery_output)

    def _fallback_run(self, discovery_output: str) -> RouterOutput:
        response = self.llm.invoke(
            [
                SystemMessage(
                    content="You are a vulnerability classification router. "
                    "Return a JSON object with 'vuln_types' (list of strings) "
                    "and 'reasoning' (string)."
                ),
                HumanMessage(
                    content=ROUTER_PROMPT.format(discovery_output=discovery_output)
                ),
            ]
        )

        try:
            text = response.content
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(text[start:end])
                return RouterOutput(**data)
        except (json.JSONDecodeError, Exception):
            pass

        return RouterOutput(vuln_types=[], reasoning="Failed to classify")
