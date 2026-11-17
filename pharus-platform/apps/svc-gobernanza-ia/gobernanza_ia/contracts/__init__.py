"""Contratos de privacidad para agentes de IA (Pydantic + Pydantic AI)."""

from gobernanza_ia.contracts.annotations import PII, Redaction, pii_fields
from gobernanza_ia.contracts.contract import (
    DataRule,
    Decision,
    LegalBasis,
    ModelProviderRule,
    PrivacyContract,
    Purpose,
    ToolRule,
)
from gobernanza_ia.contracts.enforcer import ContractEnforcer, EnforcementResult, PrivacyViolation, find_pii
from gobernanza_ia.governance.taxonomy import DataCategory, Sensitivity

__all__ = [
    "PII", "Redaction", "pii_fields", "DataRule", "Decision", "LegalBasis", "ModelProviderRule",
    "PrivacyContract", "Purpose", "ToolRule", "ContractEnforcer", "EnforcementResult",
    "PrivacyViolation", "find_pii", "DataCategory", "Sensitivity",
]
