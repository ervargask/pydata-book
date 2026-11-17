"""Aplicación del contrato de privacidad en tiempo de ejecución.

Tres puntos de mediación (como el punto de mediación del host en ArgorixLang):

1. **Entrada al modelo**: redacta los datos personales según la regla de su
   categoría y la finalidad activa; bloquea proveedores no declarados.
2. **Herramientas**: autoriza cada llamada (ALLOW / REVIEW / DENY) según la
   finalidad y las categorías presentes en los argumentos.
3. **Salida**: impide que el agente devuelva categorías no permitidas.

Cada decisión queda en el ledger de evidencia, sin valores de PII.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from gobernanza_ia.contracts.annotations import PII, Redaction, pii_fields
from gobernanza_ia.contracts.contract import Decision, PrivacyContract
from gobernanza_ia.governance.ledger import EvidenceLedger
from gobernanza_ia.governance.taxonomy import DataCategory

# --- Detectores de PII en texto libre ----------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RUT_RE = re.compile(r"\b(\d{1,2}(?:\.?\d{3}){2})-?([\dkK])\b")
PHONE_CL_RE = re.compile(r"(?:\+?56\s?)?(?:9\s?\d{4}\s?\d{4})\b")
CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def rut_valido(cuerpo: str, dv: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", cuerpo)][::-1]
    s = sum(d * (2 + i % 6) for i, d in enumerate(digits))
    r = 11 - s % 11
    esperado = "0" if r == 11 else "K" if r == 10 else str(r)
    return esperado == dv.upper()


def luhn(num: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", num)]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            n = n - 9 if n > 9 else n
        total += n
    return total % 10 == 0


@dataclass
class TextMatch:
    start: int
    end: int
    category: DataCategory
    value: str


def find_pii(text: str) -> list[TextMatch]:
    out: list[TextMatch] = []
    for m in EMAIL_RE.finditer(text):
        out.append(TextMatch(m.start(), m.end(), DataCategory.CONTACT, m.group()))
    for m in RUT_RE.finditer(text):
        if rut_valido(m.group(1), m.group(2)):
            out.append(TextMatch(m.start(), m.end(), DataCategory.NATIONAL_ID, m.group()))
    for m in CARD_RE.finditer(text):
        if luhn(m.group()):
            out.append(TextMatch(m.start(), m.end(), DataCategory.FINANCIAL, m.group()))
    for m in PHONE_CL_RE.finditer(text):
        out.append(TextMatch(m.start(), m.end(), DataCategory.CONTACT, m.group()))
    # sin solapamientos: gana el primero / más largo
    out.sort(key=lambda t: (t.start, -(t.end - t.start)))
    clean: list[TextMatch] = []
    for t in out:
        if not clean or t.start >= clean[-1].end:
            clean.append(t)
    return clean


# --- Resultado ------------------------------------------------------------------------


class Violation(BaseModel):
    code: str
    message: str
    path: str | None = None
    category: DataCategory | None = None


class EnforcementResult(BaseModel):
    decision: Decision
    payload: Any = None
    violations: list[Violation] = Field(default_factory=list)
    redacted: list[str] = Field(default_factory=list)  # rutas/categorías redactadas (nunca valores)
    evidence_id: str | None = None


class PrivacyViolation(RuntimeError):
    def __init__(self, result: EnforcementResult) -> None:
        super().__init__("; ".join(v.message for v in result.violations) or result.decision.value)
        self.result = result


# --- Enforcer -------------------------------------------------------------------------------


@dataclass
class ContractEnforcer:
    contract: PrivacyContract
    purpose: str
    ledger: EvidenceLedger | None = None
    salt: str = field(default_factory=lambda: secrets.token_hex(8))
    vault: dict[str, str] = field(default_factory=dict)  # token -> valor (llavero de PII, en memoria)

    def __post_init__(self) -> None:
        if self.contract.purpose(self.purpose) is None:
            raise ValueError(f"Finalidad «{self.purpose}» no declarada en el contrato {self.contract.id}")

    # ---------- primitivas de redacción
    def _redact_value(self, value: str, how: Redaction, category: DataCategory) -> str | None:
        if how is Redaction.NONE:
            return value
        if how is Redaction.DROP:
            return None
        if how is Redaction.HASH:
            return f"[{category.value}:{hashlib.sha256((self.salt + value).encode()).hexdigest()[:10]}]"
        if how is Redaction.TOKENIZE:
            tok = f"<{category.value.upper()}_{hashlib.sha256((self.salt + value).encode()).hexdigest()[:8]}>"
            self.vault[tok] = value
            return tok
        # MASK
        return " ".join(w[:1] + "*" * max(len(w) - 1, 2) for w in value.split()) or "***"

    def detokenize(self, text: str) -> str:
        for tok, val in self.vault.items():
            text = text.replace(tok, val)
        return text

    def _allowed(self, category: DataCategory) -> bool:
        r = self.contract.rule_for(category)
        return r is not None and self.purpose in r.purposes

    def _log(self, kind: str, subject: str, result: EnforcementResult, **detail: Any) -> EnforcementResult:
        if self.ledger is not None:
            e = self.ledger.append(
                kind,  # type: ignore[arg-type]
                subject=subject,
                decision=result.decision.value,
                contract=self.contract.id,
                contract_fp=self.contract.fingerprint()[:23],
                purpose=self.purpose,
                violations=[v.code for v in result.violations],
                redacted=result.redacted,
                **detail,
            )
            result.evidence_id = e.id
        return result

    # ---------- 0. verificación estática de un esquema (como `argorixc check`)
    def check_schema(self, model: type[BaseModel]) -> EnforcementResult:
        violations = []
        for f in pii_fields(model):
            if not self._allowed(f.pii.category):
                violations.append(
                    Violation(
                        code="PH-PC-001",
                        message=f"El campo «{f.path}» ({f.pii.category.value}) no está permitido para la finalidad «{self.purpose}»",
                        path=f.path,
                        category=f.pii.category,
                    )
                )
        res = EnforcementResult(decision=Decision.DENY if violations else Decision.ALLOW, violations=violations)
        return self._log("contract.check", model.__name__, res, fields=len(pii_fields(model)))

    # ---------- 1. entrada al modelo
    def check_provider(self, provider: str) -> EnforcementResult:
        if provider in {"test", "function"}:  # modelos de prueba locales
            return EnforcementResult(decision=Decision.ALLOW)
        if self.contract.provider_rule(provider) is None:
            res = EnforcementResult(
                decision=Decision.DENY,
                violations=[Violation(code="PH-PC-010", message=f"Proveedor de modelo «{provider}» no declarado en el contrato")],
            )
            return self._log("model.request", provider, res)
        return EnforcementResult(decision=Decision.ALLOW)

    def redact_text(self, text: str, *, destination: str = "model") -> EnforcementResult:
        """Redacta PII detectada en texto libre según el contrato."""
        violations: list[Violation] = []
        redacted: list[str] = []
        parts: list[str] = []
        last = 0
        for m in find_pii(text):
            parts.append(text[last : m.start])
            rule = self.contract.rule_for(m.category)
            if not self._allowed(m.category):
                parts.append(f"[{m.category.value} retirado]")
                violations.append(Violation(code="PH-PC-002", message=f"Dato «{m.category.value}» fuera de la finalidad «{self.purpose}»", category=m.category))
                redacted.append(m.category.value)
            else:
                how = rule.to_model if (rule and destination == "model") else Redaction.NONE
                new = self._redact_value(m.value, how, m.category)
                parts.append(new or "")
                if how is not Redaction.NONE:
                    redacted.append(m.category.value)
            last = m.end
        parts.append(text[last:])
        decision = Decision.REDACT if redacted else Decision.ALLOW
        return EnforcementResult(decision=decision, payload="".join(parts), violations=violations, redacted=redacted)

    def sanitize(self, obj: BaseModel, *, destination: str = "model") -> EnforcementResult:
        """Copia redactada de un modelo anotado con `PII`, lista para el LLM."""
        data = obj.model_dump(mode="json")
        violations: list[Violation] = []
        redacted: list[str] = []

        def apply(node: Any, path_parts: list[str], pii: PII) -> Any:
            if not path_parts:
                if node is None:
                    return None
                if not self._allowed(pii.category):
                    violations.append(Violation(code="PH-PC-002", message=f"«{pii.category.value}» fuera de la finalidad", category=pii.category))
                    return "__DROP__"
                rule = self.contract.rule_for(pii.category)
                how = pii.redaction or (rule.to_model if rule else Redaction.DROP)
                if destination != "model":
                    how = Redaction.NONE
                if how is not Redaction.NONE:
                    redacted.append(pii.category.value)
                v = self._redact_value(str(node), how, pii.category)
                return "__DROP__" if v is None else v
            head, *rest = path_parts
            if head.endswith("[]"):
                key = head[:-2]
                if isinstance(node, dict) and isinstance(node.get(key), list):
                    node[key] = [apply(item, rest, pii) for item in node[key]]
                return node
            if isinstance(node, dict) and head in node:
                res = apply(node[head], rest, pii)
                if res == "__DROP__":
                    node.pop(head)
                else:
                    node[head] = res
            return node

        for f in pii_fields(type(obj)):
            parts = f.path.replace("[].", "[]\x00").split(".")
            parts = [p for chunk in parts for p in chunk.split("\x00")]
            data = apply(data, parts, f.pii)

        decision = Decision.REDACT if redacted or violations else Decision.ALLOW
        res = EnforcementResult(decision=decision, payload=data, violations=violations, redacted=sorted(set(redacted)))
        return self._log("enforcement", type(obj).__name__, res, destination=destination)

    # ---------- 2. herramientas
    def authorize_tool(self, tool: str, args: dict[str, Any] | None = None) -> EnforcementResult:
        rule = self.contract.tool_rule(tool)
        violations: list[Violation] = []
        if rule is None:
            violations.append(Violation(code="PH-PC-020", message=f"Herramienta «{tool}» no declarada en el contrato (fail-closed)"))
            res = EnforcementResult(decision=Decision.DENY, violations=violations)
        elif self.purpose not in rule.purposes:
            violations.append(Violation(code="PH-PC-021", message=f"Herramienta «{tool}» no permitida para la finalidad «{self.purpose}»"))
            res = EnforcementResult(decision=Decision.DENY, violations=violations)
        else:
            cats = {m.category for m in find_pii(str(args or {}))}
            extra = cats - set(rule.data_allowed)
            if extra:
                violations.append(
                    Violation(code="PH-PC-022", message=f"Argumentos de «{tool}» llevan datos no permitidos: {sorted(c.value for c in extra)}")
                )
                res = EnforcementResult(decision=Decision.DENY, violations=violations)
            else:
                res = EnforcementResult(decision=rule.decision)
        return self._log("tool.authorization", tool, res)

    # ---------- 3. salida
    def check_output(self, text: str) -> EnforcementResult:
        violations = []
        out = text
        for m in reversed(find_pii(text)):
            rule = self.contract.rule_for(m.category)
            if not (rule and rule.in_output and self.purpose in rule.purposes):
                violations.append(Violation(code="PH-PC-030", message=f"La respuesta expone «{m.category.value}»", category=m.category))
                out = out[: m.start] + f"[{m.category.value} protegido]" + out[m.end :]
        res = EnforcementResult(decision=Decision.REDACT if violations else Decision.ALLOW, payload=out, violations=violations)
        return self._log("model.response", self.contract.id, res)
