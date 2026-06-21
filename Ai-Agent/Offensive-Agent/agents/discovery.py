import json

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from ..models.schemas import DiscoveryFinding, DiscoveryOutput
from ..prompts.templates import DISCOVERY_PROMPT
from ..utils.logger import get_logger

logger = get_logger("discovery_agent")


class DiscoveryAgent:
    """Identifies potential vulnerabilities from recon + web analysis data."""

    def __init__(self, config, rag_engine=None):
        self.config = config
        self.rag_engine = rag_engine
        self.llm = ChatOpenAI(
            model=config.models.discovery,
            openai_api_key=config.openai_api_key,
            temperature=0,
            max_retries=10,
        )

    def run(self, url: str, recon_data: str, web_analysis: str) -> DiscoveryOutput:
        logger.info("Running vulnerability discovery")

        prompt = DISCOVERY_PROMPT.format(
            url=url,
            recon_data=recon_data,
            web_analysis=web_analysis,
        )

        try:
            structured_llm = self.llm.with_structured_output(DiscoveryOutput)
            result = structured_llm.invoke(
                [
                    SystemMessage(content="You are a vulnerability discovery agent."),
                    HumanMessage(content=prompt),
                ]
            )
            logger.info(f"Discovery found {len(result.potential_vulns)} potential vulns")
            return result
        except Exception as e:
            logger.warning(f"Structured output failed, using fallback: {e}")
            return self._fallback_run(url, recon_data, web_analysis)

    def _fallback_run(
        self, url: str, recon_data: str, web_analysis: str
    ) -> DiscoveryOutput:
        """Fallback: parse free-text response into DiscoveryOutput."""
        prompt = DISCOVERY_PROMPT.format(
            url=url,
            recon_data=recon_data,
            web_analysis=web_analysis,
        )

        response = self.llm.invoke(
            [
                SystemMessage(
                    content="You are a vulnerability discovery agent. "
                    "Return your findings as a JSON array of objects with keys: "
                    "vuln_type, location, parameter, evidence, priority."
                ),
                HumanMessage(content=prompt),
            ]
        )

        try:
            text = response.content
            start = text.find("[")
            end = text.rfind("]") + 1
            if start >= 0 and end > start:
                findings_raw = json.loads(text[start:end])
                findings = [DiscoveryFinding(**f) for f in findings_raw]
                return DiscoveryOutput(potential_vulns=findings)
        except (json.JSONDecodeError, Exception) as parse_err:
            logger.warning(f"Fallback parse failed: {parse_err}")

        return DiscoveryOutput()
