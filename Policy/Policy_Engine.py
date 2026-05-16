import yaml
from typing import List

# ---------------------------------------------------------------------------
# Policy_Engine.py  –  Risk aggregation and auditable decision engine
# ---------------------------------------------------------------------------

_Config_Path = "Config/Gateway_Config.yaml"

def _Load_Config():
    try:
        with open(_Config_Path, "r") as F:
            return yaml.safe_load(F)
    except Exception:
        return {}

_Cfg = _Load_Config()
_Thresholds = _Cfg.get("Thresholds", {})

Pii_Weight    = float(_Thresholds.get("Pii_Weight", 0.10))
Secret_Weight = float(_Thresholds.get("Secret_Weight", 0.15))
Block_Th      = float(_Thresholds.get("Final_Risk_Block", 0.60))
Mask_Th       = float(_Thresholds.get("Mask_Threshold",   0.40))


def _Has_Secret_Entity(Pii_Entities: List[dict]) -> bool:
    Secret_Types = {"API_KEY", "CREDIT_CARD", "IBAN_CODE"}
    return any(E["type"] in Secret_Types for E in Pii_Entities)


def Decide_Policy(
    Rule_Score: float,
    Semantic_Score_Value: float,
    Pii_Entities: List[dict],
    Has_Composite: bool,
    Rule_Reason_Codes: List[str],
) -> dict:
    """
    Combine all signals and return an auditable policy decision.

    Formula:
        Final_Risk = max(Rule_Score, Semantic_Score_Value)
                     + (Pii_Weight  if PII present)
                     + (Secret_Weight if secret-type PII)

    Returns a dict with: decision, final_risk, reason_codes.
    """
    Pii_Found   = len(Pii_Entities) > 0
    Has_Secret  = _Has_Secret_Entity(Pii_Entities)

    Final_Risk = max(Rule_Score, Semantic_Score_Value)
    if Pii_Found:
        Final_Risk += Pii_Weight
    if Has_Secret:
        Final_Risk += Secret_Weight
    Final_Risk = min(Final_Risk, 1.0)

    # Build reason codes
    Reason_Codes = list(Rule_Reason_Codes)

    if Semantic_Score_Value >= 0.7:
        if "SEMANTIC_INJECTION" not in Reason_Codes:
            Reason_Codes.append("SEMANTIC_INJECTION")

    if Pii_Found:
        for E in Pii_Entities:
            Code = f"PII_{E['type']}"
            if Code not in Reason_Codes:
                Reason_Codes.append(Code)

    if Has_Composite:
        if "COMPOSITE_PII" not in Reason_Codes:
            Reason_Codes.append("COMPOSITE_PII")

    # Decision
    if Final_Risk >= Block_Th:
        Decision = "BLOCK"
    elif Pii_Found or Final_Risk >= Mask_Th:
        Decision = "MASK"
    else:
        Decision = "ALLOW"

    return {
        "decision": Decision,
        "final_risk": round(Final_Risk, 4),
        "reason_codes": Reason_Codes,
    }
