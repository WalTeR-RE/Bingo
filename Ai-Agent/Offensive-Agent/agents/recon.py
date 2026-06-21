from langchain_classic.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain_core.tools import Tool
from langchain_openai import ChatOpenAI

from ..models.schemas import ReconOutput
from ..prompts.templates import RECON_PROMPT
from ..utils.logger import get_logger
from .base_exploit import execute_command, _handle_parsing_error

logger = get_logger("recon_agent")


class ReconAgent:
    """Infrastructure reconnaissance agent — runs security tools via shell."""

    def __init__(self, config):
        self.config = config
        self.llm = ChatOpenAI(
            model=config.models.recon,
            openai_api_key=config.openai_api_key,
            temperature=0,
            max_retries=10,
        )
        self.tools = [
            Tool(
                name="shell",
                description=(
                    "Execute a shell command for reconnaissance. "
                    "Available tools: nmap, curl. "
                    "Do NOT use whatweb, ffuf, or other tools — they are not installed. "
                    "Always use non-interactive flags. Never wrap commands in backticks."
                ),
                func=lambda cmd: execute_command(
                    cmd, config.agent_limits.recon_timeout
                ),
            ),
        ]
        prompt = PromptTemplate.from_template(RECON_PROMPT)
        agent = create_react_agent(self.llm, self.tools, prompt)
        self.executor = AgentExecutor(
            agent=agent,
            tools=self.tools,
            max_iterations=20,
            handle_parsing_errors=_handle_parsing_error,
            verbose=True,
        )

    def run(self, url: str) -> ReconOutput:
        logger.info(f"Starting recon on {url}")
        try:
            result = self.executor.invoke({"url": url})
            raw_output = result.get("output", "")
            return self._parse_output(url, raw_output)
        except Exception as e:
            logger.error(f"Recon failed: {e}")
            return ReconOutput(target_url=url, raw_output=str(e))

    @staticmethod
    def _parse_output(url: str, raw: str) -> ReconOutput:
        """Best-effort extraction from the agent's free-text output."""
        output = ReconOutput(target_url=url, raw_output=raw)

        import re

        tech_patterns = [
            r"(?:Technology|Framework|CMS|Server|Language):\s*(.+)",
            r"(?:Apache|Nginx|PHP|Python|Node|Ruby|Java|WordPress|Django|Flask|Laravel|Express|jQuery)\S*",
        ]
        techs = set()
        for pattern in tech_patterns:
            for match in re.findall(pattern, raw, re.IGNORECASE):
                techs.add(match.strip())
        output.technologies = list(techs)[:20]

        port_matches = re.findall(r"(\d{1,5})/(?:tcp|udp)\s+open\s+(\S+)", raw)
        for port, service in port_matches:
            output.open_ports.append({"port": int(port), "service": service})

        dir_matches = re.findall(
            r"(?:Status|→)\s*(?:200|301|302|403)\s*.*?(/\S+)", raw
        )
        output.directories = list(set(dir_matches))[:50]

        return output
