"""Detectores estáticos de activos de IA.

Funcionan sin ejecutar código del cliente (análisis AST para Python y
expresiones regulares para JS/TS, configuraciones MCP y pasaportes Argorix).
Nunca leen ni almacenan VALORES de secretos: sólo el nombre de la variable y
la ubicación del hallazgo.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from gobernanza_ia.governance.taxonomy import CATEGORY_HINTS, DataCategory
from gobernanza_ia.scanner.models import (
    AgentAsset,
    AssetKind,
    Finding,
    Framework,
    Location,
    ModelRef,
    Severity,
    SideEffect,
    ToolRef,
)

# --- Firmas -----------------------------------------------------------------

IMPORT_FRAMEWORKS: dict[str, Framework] = {
    "pydantic_ai": Framework.PYDANTIC_AI,
    "langgraph": Framework.LANGGRAPH,
    "langchain": Framework.LANGCHAIN,
    "langchain_core": Framework.LANGCHAIN,
    "langchain_openai": Framework.LANGCHAIN,
    "langchain_anthropic": Framework.LANGCHAIN,
    "crewai": Framework.CREWAI,
    "autogen": Framework.AUTOGEN,
    "autogen_agentchat": Framework.AUTOGEN,
    "llama_index": Framework.LLAMAINDEX,
    "agents": Framework.OPENAI_AGENTS,  # OpenAI Agents SDK
    "openai": Framework.OPENAI_SDK,
    "anthropic": Framework.ANTHROPIC_SDK,
    "google.genai": Framework.GOOGLE_GENAI,
    "google.generativeai": Framework.GOOGLE_GENAI,
    "vertexai": Framework.GOOGLE_GENAI,
    "mcp": Framework.MCP_SERVER,
    "fastmcp": Framework.MCP_SERVER,
}

# Constructores que crean un agente (loop autónomo con herramientas).
AGENT_CONSTRUCTORS: dict[str, Framework] = {
    "Agent": Framework.PYDANTIC_AI,  # se corrige según imports (crewai / openai agents)
    "create_react_agent": Framework.LANGGRAPH,
    "create_tool_calling_agent": Framework.LANGCHAIN,
    "create_openai_functions_agent": Framework.LANGCHAIN,
    "AgentExecutor": Framework.LANGCHAIN,
    "AssistantAgent": Framework.AUTOGEN,
    "ReActAgent": Framework.LLAMAINDEX,
    "FunctionAgent": Framework.LLAMAINDEX,
    "FastMCP": Framework.MCP_SERVER,
}

LLM_CLIENT_CALLS = {
    # (atributo final, framework)
    ("completions", "create"): Framework.OPENAI_SDK,
    ("responses", "create"): Framework.OPENAI_SDK,
    ("messages", "create"): Framework.ANTHROPIC_SDK,
    ("models", "generate_content"): Framework.GOOGLE_GENAI,
}

CHAT_MODEL_CLASSES = {
    "ChatOpenAI": "openai",
    "AzureChatOpenAI": "azure",
    "ChatAnthropic": "anthropic",
    "ChatVertexAI": "google",
    "ChatGoogleGenerativeAI": "google",
    "ChatOllama": "ollama",
    "ChatBedrock": "bedrock",
    "OpenAIModel": "openai",
    "OpenAIChatModel": "openai",
    "AnthropicModel": "anthropic",
    "GoogleModel": "google",
}

SIDE_EFFECT_CALLS: dict[SideEffect, tuple[str, ...]] = {
    SideEffect.NETWORK: ("requests.", "httpx.", "urllib.request", "aiohttp.", "fetch(", "axios."),
    SideEffect.EMAIL: ("smtplib", "send_mail", "send_email", "sendgrid", "ses.send", "enviar_correo"),
    SideEffect.PAYMENT: ("stripe.", "transbank", "webpay", "charge", "refund", "reembolso", "cobro"),
    SideEffect.CODE_EXEC: ("subprocess.", "os.system", "eval(", "exec(", "child_process"),
    SideEffect.DATABASE: (".execute(", "cursor", "session.add", ".commit(", "insert into", "update ", "delete from"),
    SideEffect.FS_WRITE: (".write_text(", ".write_bytes(", "shutil.", "os.remove", "unlink("),
}
FS_OPEN_WRITE_RE = re.compile(r"open\([^)]*['\"][wax]b?\+?['\"]")

APPROVAL_HINTS = ("requires_approval", "ApprovalRequired", "DeferredToolRequests", "human_in_the_loop", "interrupt(", "input(")
CONTRACT_HINTS = ("PrivacyContract", "ContractEnforcer", "PrivacyGuard", "gobernanza_ia.contracts")
OWNER_RE = re.compile(r"(?:owner|responsable|dueno|dueño)\s*[:=]\s*[\"']([^\"']+)[\"']", re.I)

SECRET_ENV_RE = re.compile(r"(?:os\.environ(?:\.get)?\s*[\[(]\s*|os\.getenv\(\s*|process\.env\.)[\"']?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*)")
HARDCODED_SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{30,}|ghp_[A-Za-z0-9]{30,})")

PROVIDER_PREFIXES = ("openai", "anthropic", "google-gla", "google-vertex", "google", "groq", "mistral", "bedrock", "ollama", "azure", "cohere", "deepseek", "test")


def provider_from_model_string(model: str) -> tuple[str, str | None]:
    """'openai:gpt-4o' → ('openai', 'gpt-4o'); 'claude-3-5-sonnet' → ('anthropic', ...)."""
    if ":" in model:
        p, m = model.split(":", 1)
        p = {"google-gla": "google", "google-vertex": "google"}.get(p, p)
        return p, m
    low = model.lower()
    if low.startswith(("gpt", "o1", "o3", "o4")):
        return "openai", model
    if low.startswith("claude"):
        return "anthropic", model
    if low.startswith("gemini"):
        return "google", model
    if low.startswith(("llama", "mistral", "qwen")):
        return "ollama", model
    return "unknown", model


def categories_in_text(text: str) -> set[DataCategory]:
    low = text.lower()
    return {cat for cat, hints in CATEGORY_HINTS.items() if any(h in low for h in hints)}


@dataclass
class FileResult:
    assets: list[AgentAsset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


# --- Python (AST) -------------------------------------------------------------


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _kw(call: ast.Call, *names: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg in names:
            return kw.value
    return None


def _side_effects(src: str) -> set[SideEffect]:
    low = src.lower()
    out = {fx for fx, pats in SIDE_EFFECT_CALLS.items() if any(p.lower() in low for p in pats)}
    if FS_OPEN_WRITE_RE.search(src):
        out.add(SideEffect.FS_WRITE)
    return out


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, source: str) -> None:
        self.source = source
        self.frameworks: set[Framework] = set()
        self.imported_names: dict[str, str] = {}  # alias -> módulo
        self.agents: list[tuple[str, Framework, ast.Call]] = []  # (variable, framework, call)
        self.models: list[ModelRef] = []
        self.tools: list[tuple[str | None, ToolRef]] = []  # (variable del agente, tool)
        self.llm_calls: list[tuple[Framework, ast.Call]] = []
        self.file = ""

    # imports
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self._register_import(a.name, a.asname or a.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for a in node.names:
            self.imported_names[a.asname or a.name] = mod
        self._register_import(mod, None)

    def _register_import(self, mod: str, alias: str | None) -> None:
        for prefix, fw in IMPORT_FRAMEWORKS.items():
            if mod == prefix or mod.startswith(prefix + "."):
                self.frameworks.add(fw)
        if alias:
            self.imported_names[alias] = mod

    # asignaciones: agent = Agent(...)
    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            name = _dotted(node.value.func).split(".")[-1]
            target = node.targets[0]
            var = target.id if isinstance(target, ast.Name) else _dotted(target)
            if name in AGENT_CONSTRUCTORS:
                fw = self._framework_for_constructor(name)
                if fw is not None:
                    self.agents.append((var, fw, node.value))
        self.generic_visit(node)

    def _framework_for_constructor(self, name: str) -> Framework | None:
        mod = self.imported_names.get(name, "")
        if name == "Agent":
            if mod.startswith("crewai"):
                return Framework.CREWAI
            if mod == "agents":
                return Framework.OPENAI_AGENTS
            if mod.startswith("pydantic_ai"):
                return Framework.PYDANTIC_AI
            return None  # 'Agent' de otra librería: no lo contamos
        return AGENT_CONSTRUCTORS[name]

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted(node.func)
        parts = dotted.split(".")
        last = parts[-1]
        # Modelos instanciados explícitamente
        if last in CHAT_MODEL_CLASSES:
            m = _const_str(node.args[0] if node.args else None) or _const_str(_kw(node, "model", "model_name"))
            self.models.append(ModelRef(provider=CHAT_MODEL_CLASSES[last], model=m, location=Location(file=self.file, line=node.lineno)))
        # Llamadas directas a SDK
        if len(parts) >= 2 and tuple(parts[-2:]) in LLM_CLIENT_CALLS:
            fw = LLM_CLIENT_CALLS[tuple(parts[-2:])]  # type: ignore[index]
            self.llm_calls.append((fw, node))
            m = _const_str(_kw(node, "model"))
            provider = {Framework.OPENAI_SDK: "openai", Framework.ANTHROPIC_SDK: "anthropic", Framework.GOOGLE_GENAI: "google"}[fw]
            self.models.append(ModelRef(provider=provider, model=m, location=Location(file=self.file, line=node.lineno)))
        self.generic_visit(node)

    def _tool_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str | None, bool] | None:
        """Devuelve (variable_del_agente, requiere_aprobación) si la función es una tool."""
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            d = _dotted(dec)
            parts = d.split(".")
            approval = bool(call and _kw(call, "requires_approval") is not None and getattr(_kw(call, "requires_approval"), "value", False))
            if parts[-1] in ("tool", "tool_plain") and len(parts) == 2:  # @agent.tool
                return parts[0], approval
            if parts[-1] in ("tool", "function_tool") and len(parts) == 1:  # @tool (langchain / openai agents)
                return None, approval
            if parts[-1] == "tool" and parts[0] in ("mcp", "server", "app"):  # @mcp.tool()
                return parts[0], approval
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_fn(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_fn(node)

    def _visit_fn(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        info = self._tool_decorator(node)
        if info is not None:
            agent_var, approval = info
            body = ast.get_source_segment(self.source, node) or ""
            approval = approval or any(h in body for h in ("ApprovalRequired",))
            self.tools.append(
                (
                    agent_var,
                    ToolRef(
                        name=node.name,
                        location=Location(file=self.file, line=node.lineno),
                        side_effects=_side_effects(body.split("\n", 1)[-1]),
                        requires_approval=approval,
                    ),
                )
            )
        self.generic_visit(node)


def scan_python(path: Path, rel: str, root_label: str) -> FileResult:
    res = FileResult()
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return res
    v = _PyVisitor(source)
    v.file = rel
    v.visit(tree)
    if not v.frameworks and not v.agents and not v.llm_calls:
        return res

    file_categories = categories_in_text(source)
    secret_refs = sorted(set(SECRET_ENV_RE.findall(source)))
    hardcoded = HARDCODED_SECRET_RE.findall(source)
    hitl = any(h in source for h in APPROVAL_HINTS)
    has_contract = any(h in source for h in CONTRACT_HINTS)
    owner_m = OWNER_RE.search(source)
    owner = owner_m.group(1) if owner_m else None

    for line_no, line in enumerate(source.splitlines(), 1):
        if HARDCODED_SECRET_RE.search(line):
            res.findings.append(
                Finding(
                    code="PH-IA-010",
                    title="Credencial de proveedor de IA escrita en el código",
                    severity=Severity.CRITICAL,
                    location=Location(file=rel, line=line_no),
                    recommendation="Rotar la credencial y moverla a Secret Manager; nunca versionarla.",
                )
            )

    def build(name: str, kind: AssetKind, fw: Framework, line: int, call: ast.Call | None, agent_var: str | None) -> AgentAsset:
        models = list(v.models)
        if call is not None:
            mstr = _const_str(call.args[0] if call.args else None) or _const_str(_kw(call, "model", "llm"))
            if mstr:
                p, m = provider_from_model_string(mstr)
                models.insert(0, ModelRef(provider=p, model=m, location=Location(file=rel, line=line)))
        tools = [t for var, t in v.tools if agent_var is None or var in (None, agent_var)]
        agent_name = None
        if call is not None:
            agent_name = _const_str(_kw(call, "name", "role"))
        return AgentAsset(
            name=agent_name or name,
            kind=kind,
            framework=fw,
            source=root_label,
            location=Location(file=rel, line=line),
            models=_dedupe_models(models),
            tools=tools,
            data_categories=file_categories,
            secret_refs=secret_refs,
            hardcoded_secrets=len(hardcoded),
            human_in_loop=hitl or any(t.requires_approval for t in tools),
            has_privacy_contract=has_contract,
            owner=owner,
        )

    for var, fw, call in v.agents:
        kind = AssetKind.MCP_SERVER if fw is Framework.MCP_SERVER else AssetKind.AGENT
        res.assets.append(build(var, kind, fw, call.lineno, call, var))

    if not v.agents and v.llm_calls:
        fw, call = v.llm_calls[0]
        res.assets.append(build(Path(rel).stem, AssetKind.LLM_INTEGRATION, fw, call.lineno, None, None))
    return res


def _dedupe_models(models: list[ModelRef]) -> list[ModelRef]:
    seen: set[tuple[str, str | None]] = set()
    out = []
    for m in models:
        k = (m.provider, m.model)
        if k not in seen:
            seen.add(k)
            out.append(m)
    return out


# --- JS / TS ---------------------------------------------------------------------

JS_SIGNATURES: list[tuple[re.Pattern[str], Framework, str]] = [
    (re.compile(r"from\s+['\"]openai['\"]|require\(['\"]openai['\"]\)"), Framework.OPENAI_SDK, "openai"),
    (re.compile(r"@anthropic-ai/sdk"), Framework.ANTHROPIC_SDK, "anthropic"),
    (re.compile(r"@google/(?:genai|generative-ai)|@google-cloud/vertexai|aiplatform\.googleapis\.com|:generateContent"), Framework.GOOGLE_GENAI, "google"),
    (re.compile(r"from\s+['\"]ai['\"]|@ai-sdk/"), Framework.VERCEL_AI, "unknown"),
    (re.compile(r"@langchain/"), Framework.LANGCHAIN, "unknown"),
    (re.compile(r"@modelcontextprotocol/sdk"), Framework.MCP_SERVER, "unknown"),
]
JS_MODEL_RE = re.compile(r"model\s*[:=]\s*['\"]([\w.\-:/]+)['\"]")


def scan_js(path: Path, rel: str, root_label: str) -> FileResult:
    res = FileResult()
    src = path.read_text(encoding="utf-8", errors="replace")
    for pat, fw, provider in JS_SIGNATURES:
        m = pat.search(src)
        if not m:
            continue
        line = src[: m.start()].count("\n") + 1
        models = []
        for mm in JS_MODEL_RE.finditer(src):
            p, name = provider_from_model_string(mm.group(1))
            models.append(ModelRef(provider=p if p != "unknown" else provider, model=name, location=Location(file=rel, line=src[: mm.start()].count("\n") + 1)))
        res.assets.append(
            AgentAsset(
                name=Path(rel).stem,
                kind=AssetKind.MCP_SERVER if fw is Framework.MCP_SERVER else AssetKind.LLM_INTEGRATION,
                framework=fw,
                source=root_label,
                location=Location(file=rel, line=line),
                models=_dedupe_models(models) or [ModelRef(provider=provider, location=Location(file=rel, line=line))],
                data_categories=categories_in_text(src),
                secret_refs=sorted(set(SECRET_ENV_RE.findall(src))),
                hardcoded_secrets=len(HARDCODED_SECRET_RE.findall(src)),
                human_in_loop=any(h in src for h in APPROVAL_HINTS),
                has_privacy_contract=any(h in src for h in CONTRACT_HINTS),
            )
        )
        break  # un activo por archivo
    return res


# --- Configuración MCP --------------------------------------------------------------


def scan_mcp_config(path: Path, rel: str, root_label: str) -> FileResult:
    res = FileResult()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return res
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return res
    for name, cfg in servers.items():
        cfg = cfg if isinstance(cfg, dict) else {}
        cmd = " ".join([str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", [])] + [str(cfg.get("url", ""))])
        env_names = sorted((cfg.get("env") or {}).keys())
        fx: set[SideEffect] = set()
        low = cmd.lower() + " " + name.lower()
        if any(k in low for k in ("filesystem", "fs", "files")):
            fx.add(SideEffect.FS_WRITE)
        if any(k in low for k in ("postgres", "mysql", "sqlite", "db", "bigquery")):
            fx.add(SideEffect.DATABASE)
        if any(k in low for k in ("http", "fetch", "browser", "puppeteer", "playwright", "slack", "gmail")):
            fx.add(SideEffect.NETWORK)
        if any(k in low for k in ("shell", "exec", "terminal", "commander")):
            fx.add(SideEffect.CODE_EXEC)
        asset = AgentAsset(
            name=name,
            kind=AssetKind.MCP_SERVER,
            framework=Framework.MCP_SERVER,
            source=root_label,
            location=Location(file=rel, line=1),
            tools=[ToolRef(name=f"{name}:*", location=Location(file=rel, line=1), side_effects=fx)],
            secret_refs=env_names,
            data_categories=categories_in_text(cmd + " " + name),
        )
        # valores literales en env de la config: probable secreto versionado
        for k, val in (cfg.get("env") or {}).items():
            if isinstance(val, str) and val and not val.startswith("${") and any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD")):
                asset.hardcoded_secrets += 1
                res.findings.append(
                    Finding(
                        code="PH-IA-011",
                        title=f"Secreto literal en la configuración MCP «{name}» ({k})",
                        severity=Severity.HIGH,
                        location=Location(file=rel, line=1),
                        recommendation="Referenciar la variable de entorno (${VAR}) en lugar del valor.",
                    )
                )
        res.assets.append(asset)
    return res


# --- Pasaportes ArgorixLang (.argx) -------------------------------------------------

PASSPORT_RE = re.compile(r"passport\s+(\w+)\s*\{(.*?)\n\}", re.S)
FIELD_RE = re.compile(r"^\s*(\w+)\s+(\"[^\"]*\"|\[[^\]]*\]|\w+)\s*$", re.M)
AGENT_RE = re.compile(r"agent\s+(\w+)\s*\{(.*?)\n\}", re.S)
TOOL_DECL_RE = re.compile(r"tool\s+(\w+)\s*\{[^}]*capability\s+([\w.]+)")
MODEL_DECL_RE = re.compile(r"model\s+(\w+)\s*\{[^}]*provider\s+(\w+)")


def _argx_value(raw: str) -> object:
    raw = raw.strip()
    if raw.startswith("["):
        return re.findall(r"\"([^\"]*)\"", raw)
    return raw.strip('"')


def scan_argorix(path: Path, rel: str, root_label: str) -> FileResult:
    """Lee pasaportes de agentes declarados en ArgorixLang y los registra
    como agentes *declarados* (no shadow)."""
    res = FileResult()
    src = path.read_text(encoding="utf-8", errors="replace")
    tools = {name: cap for name, cap in TOOL_DECL_RE.findall(src)}
    models = {name: prov for name, prov in MODEL_DECL_RE.findall(src)}
    agents_body = {m.group(1): m.group(2) for m in AGENT_RE.finditer(src)}
    for m in PASSPORT_RE.finditer(src):
        fields = {k: _argx_value(v) for k, v in FIELD_RE.findall(m.group(2))}
        agent = str(fields.get("agent", m.group(1)))
        body = agents_body.get(agent, "")
        agent_tools = [t for t in tools if t in body]
        agent_models = [mm for mm in models if mm in body]
        scope = fields.get("data_scope", [])
        cats = categories_in_text(" ".join(scope) if isinstance(scope, list) else str(scope))
        res.assets.append(
            AgentAsset(
                name=str(fields.get("agent_name", agent)),
                kind=AssetKind.DECLARED_AGENT,
                framework=Framework.ARGORIX,
                source=root_label,
                location=Location(file=rel, line=src[: m.start()].count("\n") + 1),
                models=[ModelRef(provider=models[mm], model=mm, location=Location(file=rel, line=1)) for mm in agent_models],
                tools=[ToolRef(name=t, location=Location(file=rel, line=1), requires_approval="approval" in src) for t in agent_tools],
                data_categories=cats,
                has_passport=True,
                human_in_loop="approval granted" in body or "action review" in src,
                owner=str(fields.get("provider")) if fields.get("provider") else None,
                declared=fields,
            )
        )
    return res
