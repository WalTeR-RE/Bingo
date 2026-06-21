import json

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from ..models.schemas import AttackPlan
from ..prompts.templates import PLANNER_PROMPT
from ..utils.logger import console_print, get_logger

logger = get_logger("planner_agent")


class PlannerAgent:
    """Creates step-by-step attack plans for each vulnerability type."""

    def __init__(self, config, rag_engine=None):
        self.config = config
        self.rag_engine = rag_engine
        self.llm = ChatOpenAI(
            model=config.models.planner,
            openai_api_key=config.openai_api_key,
            temperature=0,
            max_retries=4,
            max_tokens=3000,
        )

    def run(
        self,
        vuln_type: str,
        url: str,
        parameter: str = "",
        evidence: str = "",
        tech_stack: str = "",
        previous_attempt: str = "",
    ) -> AttackPlan:
        action = "Re-planning" if previous_attempt else "Planning"
        logger.info(f"{action} attack for {vuln_type} on {url}")

        rag_context = ""
        if self.rag_engine:
            rag_context = self.rag_engine.get_context(
                f"{vuln_type} exploitation techniques and tool commands",
                vuln_type=vuln_type,
                top_k=5,
            )

        prompt = PLANNER_PROMPT.format(
            vuln_type=vuln_type,
            url=url,
            parameter=parameter,
            evidence=evidence,
            tech_stack=tech_stack,
            rag_context=rag_context,
        )

        if previous_attempt:
            prompt += (
                "\n\n=== PREVIOUS ATTEMPT THAT FAILED ===\n"
                f"{previous_attempt}\n"
                "The above commands were already run and did NOT confirm the vulnerability. "
                "Diagnose WHY it failed, then produce a DIFFERENT, smarter plan: try other "
                "payloads, encodings, parameters, HTTP methods, or endpoints. Do NOT repeat "
                "the same commands that already failed."
            )

        try:
            structured_llm = self.llm.with_structured_output(AttackPlan)
            result = structured_llm.invoke(
                [
                    SystemMessage(content="You are an attack planning agent."),
                    HumanMessage(content=prompt),
                ]
            )
            self._log_plan(vuln_type, result)
            return result
        except Exception as e:
            logger.warning(f"Structured planner failed, using fallback: {e}")
            plan = self._fallback_run(vuln_type, url, prompt)
            self._log_plan(vuln_type, plan)
            return plan

    @staticmethod
    def _log_plan(vuln_type, plan):
        steps = plan.steps or []
        logger.info(f"ATTACK PLAN [{vuln_type}] — {len(steps)} steps:")
        console_lines = [f"\n=== ATTACK PLAN [{vuln_type}] — {len(steps)} steps ==="]
        for s in steps:
            detail = (s.command or s.action or "").strip().replace("\n", " ")[:160]
            logger.info(f"   [{vuln_type}] {s.step_number}. ({s.tool or 'shell'}) {detail}")
            console_lines.append(f"  {s.step_number}. ({s.tool or 'shell'}) {detail}")
        if plan.fallback_steps:
            logger.info(f"   [{vuln_type}] + {len(plan.fallback_steps)} fallback steps")
            console_lines.append(f"  + {len(plan.fallback_steps)} fallback steps")
        console_print("\n".join(console_lines))

    def _fallback_run(
        self, vuln_type: str, url: str, prompt: str
    ) -> AttackPlan:
        response = self.llm.invoke(
            [
                SystemMessage(
                    content="You are an attack planning agent. "
                    "Return a JSON object with 'vuln_type', 'target_url', "
                    "'parameter', 'steps' (array of {step_number, action, tool, "
                    "command, expected_outcome}), and 'fallback_steps'."
                ),
                HumanMessage(content=prompt),
            ]
        )

        try:
            text = response.content
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(text[start:end])
                return AttackPlan(**data)
        except (json.JSONDecodeError, Exception):
            pass

        return AttackPlan(vuln_type=vuln_type, target_url=url)
