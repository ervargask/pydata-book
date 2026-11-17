"""Modelo de datos del inventario de agentes de IA (AI-BOM)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, computed_field

from gobernanza_ia.governance.taxonomy import DataCategory


class Framework(str, Enum):
    PYDANTIC_AI = "pydantic_ai"
    LANGCHAIN = "langchain"
    LANGGRAPH = "langgraph"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    LLAMAINDEX = "llamaindex"
    OPENAI_AGENTS = "openai_agents"
    OPENAI_SDK = "openai_sdk"
    ANTHROPIC_SDK = "anthropic_sdk"
    GOOGLE_GENAI = "google_genai"
    VERCEL_AI = "vercel_ai"
    MCP_SERVER = "mcp_server"
    ARGORIX = "argorix"
    UNKNOWN = "unknown"


class AssetKind(str, Enum):
    AGENT = "agent"  # agente autónomo con loop de herramientas
    LLM_INTEGRATION = "llm_integration"  # llamada directa a un modelo
    MCP_SERVER = "mcp_server"  # servidor de herramientas para agentes
    DECLARED_AGENT = "declared_agent"  # agente con pasaporte Argorix declarado


class SideEffect(str, Enum):
    NETWORK = "network"
    FS_WRITE = "fs_write"
    DATABASE = "database"
    EMAIL = "email"
    PAYMENT = "payment"
    CODE_EXEC = "code_exec"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskTier(str, Enum):
    MINIMAL = "minimal"
    LIMITED = "limited"
    HIGH = "high"
    CRITICAL = "critical"


class Location(BaseModel):
    file: str
    line: int = 0


class ToolRef(BaseModel):
    name: str
    location: Location
    side_effects: set[SideEffect] = Field(default_factory=set)
    requires_approval: bool = False


class ModelRef(BaseModel):
    provider: str  # openai, anthropic, google, ollama, unknown...
    model: str | None = None
    location: Location

    @property
    def is_external(self) -> bool:
        return self.provider not in {"ollama", "local", "vllm", "test", "simulated"}


class Finding(BaseModel):
    code: str  # p.ej. PH-AI-001
    title: str
    severity: Severity
    location: Location | None = None
    recommendation: str = ""


class RiskFactor(BaseModel):
    name: str
    points: int
    reason: str


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    tier: RiskTier
    factors: list[RiskFactor] = Field(default_factory=list)
    eu_ai_act_class: str = "no determinado"


class AgentAsset(BaseModel):
    """Un activo de IA descubierto. `id` es estable entre escaneos."""

    name: str
    kind: AssetKind
    framework: Framework
    source: str  # raíz/repositorio escaneado
    location: Location
    models: list[ModelRef] = Field(default_factory=list)
    tools: list[ToolRef] = Field(default_factory=list)
    mcp_servers: list[str] = Field(default_factory=list)
    data_categories: set[DataCategory] = Field(default_factory=set)
    secret_refs: list[str] = Field(default_factory=list)  # sólo NOMBRES de variables, nunca valores
    hardcoded_secrets: int = 0
    human_in_loop: bool = False
    has_privacy_contract: bool = False
    has_passport: bool = False
    declared: dict[str, object] = Field(default_factory=dict)  # metadatos del pasaporte Argorix
    owner: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskAssessment | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        key = f"{self.source}|{self.location.file}|{self.kind.value}|{self.name}"
        return "ai_" + hashlib.sha1(key.encode()).hexdigest()[:12]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def shadow(self) -> bool:
        """'Shadow AI': agente sin pasaporte ni contrato de privacidad ni dueño."""
        return not (self.has_passport or self.has_privacy_contract or self.owner)


class ScanSummary(BaseModel):
    assets: int
    agents: int
    shadow: int
    by_tier: dict[RiskTier, int]
    by_framework: dict[str, int]
    external_providers: list[str]
    sensitive_assets: int


class ScanReport(BaseModel):
    scan_id: str
    root: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    files_scanned: int = 0
    assets: list[AgentAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)  # hallazgos sin agente asociado

    def summary(self) -> ScanSummary:
        from collections import Counter

        tiers = Counter(a.risk.tier for a in self.assets if a.risk)
        return ScanSummary(
            assets=len(self.assets),
            agents=sum(a.kind in (AssetKind.AGENT, AssetKind.DECLARED_AGENT) for a in self.assets),
            shadow=sum(a.shadow for a in self.assets),
            by_tier={t: tiers.get(t, 0) for t in RiskTier},
            by_framework=dict(Counter(a.framework.value for a in self.assets)),
            external_providers=sorted({m.provider for a in self.assets for m in a.models if m.is_external}),
            sensitive_assets=sum(
                any(c.value in {"health", "biometric", "genetic", "minors", "political", "religion", "sexual_orientation"} for c in a.data_categories)
                for a in self.assets
            ),
        )
