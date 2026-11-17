"""Integración del contrato de privacidad con Pydantic AI.

`PrivacyGuard` es una *capability* de Pydantic AI: se agrega a cualquier
`Agent` y media, sin tocar el código de las herramientas:

- `before_model_request`: verifica el proveedor y redacta la PII de los
  mensajes (prompt del usuario y resultados de herramientas) antes de que
  salgan hacia el modelo.
- `before_tool_execute`: autoriza la herramienta. DENY → `ToolFailed`
  (el modelo ve el rechazo y se adapta); REVIEW → `ApprovalRequired`
  (human-in-the-loop, acción `manual_verify` en Pharus).
- `after_tool_execute`: redacta PII del resultado de la herramienta.
- `after_run`: impide que la salida final exponga categorías no permitidas.

Uso::

    agent = Agent('openai:gpt-5.2', capabilities=[PrivacyGuard(enforcer)])
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any

from pydantic_ai import ApprovalRequired, RunContext, ToolFailed
from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.messages import ModelRequest, ToolCallPart, ToolReturnPart, UserPromptPart
from pydantic_ai.models import ModelRequestContext

from gobernanza_ia.contracts.contract import Decision
from gobernanza_ia.contracts.enforcer import ContractEnforcer, PrivacyViolation


def _provider_of(model: Any) -> str:
    system = getattr(model, "system", None) or "unknown"
    return {"google-gla": "google", "google-vertex": "google", "google-genai": "google"}.get(system, system)


@dataclass
class PrivacyGuard(AbstractCapability[Any]):
    enforcer: ContractEnforcer
    redact_tool_results: bool = True
    check_final_output: bool = True

    # 1. Entrada al modelo -------------------------------------------------------
    async def before_model_request(self, ctx: RunContext[Any], request_context: ModelRequestContext) -> ModelRequestContext:
        prov = self.enforcer.check_provider(_provider_of(request_context.model))
        if prov.decision is Decision.DENY:
            raise PrivacyViolation(prov)

        new_messages = []
        redacted_any: list[str] = []
        for msg in request_context.messages:
            if isinstance(msg, ModelRequest):
                parts = []
                for p in msg.parts:
                    if isinstance(p, UserPromptPart) and isinstance(p.content, str):
                        r = self.enforcer.redact_text(p.content)
                        redacted_any += r.redacted
                        p = dataclasses.replace(p, content=r.payload)
                    elif isinstance(p, ToolReturnPart) and isinstance(p.content, str):
                        r = self.enforcer.redact_text(p.content)
                        redacted_any += r.redacted
                        p = dataclasses.replace(p, content=r.payload)
                    parts.append(p)
                msg = dataclasses.replace(msg, parts=parts)
            new_messages.append(msg)
        request_context.messages[:] = new_messages
        if self.enforcer.ledger is not None and redacted_any:
            self.enforcer.ledger.append(
                "model.request",
                subject=_provider_of(request_context.model),
                decision=Decision.REDACT.value,
                contract=self.enforcer.contract.id,
                purpose=self.enforcer.purpose,
                redacted=sorted(set(redacted_any)),
            )
        return request_context

    # 2. Herramientas -----------------------------------------------------------------
    async def before_tool_execute(self, ctx: RunContext[Any], *, call: ToolCallPart, tool_def: Any, args: Any) -> Any:
        raw = args if isinstance(args, dict) else getattr(args, "__dict__", {"args": str(args)})
        res = self.enforcer.authorize_tool(call.tool_name, raw)
        if res.decision is Decision.DENY:
            raise ToolFailed("Bloqueado por el contrato de privacidad: " + "; ".join(v.message for v in res.violations))
        if res.decision is Decision.REVIEW and not ctx.tool_call_approved:
            raise ApprovalRequired(metadata={"contract": self.enforcer.contract.id, "evidence": res.evidence_id})
        return args

    async def after_tool_execute(self, ctx: RunContext[Any], *, call: ToolCallPart, tool_def: Any, args: Any, result: Any) -> Any:
        if self.redact_tool_results and isinstance(result, str):
            return self.enforcer.redact_text(result).payload
        return result

    # 3. Salida -----------------------------------------------------------------------
    async def after_run(self, ctx: RunContext[Any], *, result: Any) -> Any:
        if self.check_final_output and isinstance(getattr(result, "output", None), str):
            chk = self.enforcer.check_output(result.output)
            if chk.violations:
                result = dataclasses.replace(result, output=chk.payload) if dataclasses.is_dataclass(result) else result
        return result
