from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import time
import uuid

from Detectors.Rule_Detector import Detect_Rule_Attack
from Detectors.Semantic_Detector import Semantic_Score, Retrain_Model
from Utils.Language import Detect_Language, Get_Language_Name, Is_Multilingual
from Pii.Presidio_Custom import Analyze_Pii
from Policy.Policy_Engine import Decide_Policy
from Utils.Logging_Utils import Log_Request, Read_Audit_Log

# ---------------------------------------------------------------------------
# Main.py  –  FastAPI entry point for the LLM Security Gateway
# ---------------------------------------------------------------------------

Application = FastAPI(
    title="LLM Security Gateway",
    description="Robust multilingual pre-model security gateway",
    version="1.0.0",
)


# ------------------------------------------------------------------
# Request / Response models
# ------------------------------------------------------------------

class Analyze_Request(BaseModel):
    Text: str
    Input_Id: Optional[str] = None


class Health_Response(BaseModel):
    Status: str
    Version: str


# ------------------------------------------------------------------
# Helper: build the full analysis pipeline result
# ------------------------------------------------------------------

def _Run_Pipeline(Text: str, Input_Id: str) -> dict:
    Start_Time = time.time()

    # Language detection
    Language_Code = Detect_Language(Text)
    Language_Name = Get_Language_Name(Language_Code)
    Mixed = Is_Multilingual(Text)

    # Rule-based detection
    Rule_Score, Rule_Reason_Codes = Detect_Rule_Attack(Text)

    # Semantic detection
    Semantic_Score_Value = Semantic_Score(Text)

    # PII analysis
    Pii_Entities, Safe_Text, Has_Composite = Analyze_Pii(Text)

    # Policy decision
    Policy = Decide_Policy(
        Rule_Score=Rule_Score,
        Semantic_Score_Value=Semantic_Score_Value,
        Pii_Entities=Pii_Entities,
        Has_Composite=Has_Composite,
        Rule_Reason_Codes=Rule_Reason_Codes,
    )

    Latency_Ms = round((time.time() - Start_Time) * 1000, 2)

    Decision   = Policy["decision"]
    Final_Risk = Policy["final_risk"]
    Reason_Codes = Policy["reason_codes"]

    Response = {
        "input_id":       Input_Id,
        "language":       Language_Code,
        "language_name":  Language_Name,
        "is_multilingual": Mixed,
        "rule_score":     round(Rule_Score, 4),
        "semantic_score": round(Semantic_Score_Value, 4),
        "pii_entities":   Pii_Entities,
        "final_risk":     Final_Risk,
        "decision":       Decision,
        "safe_text":      Safe_Text if Decision in ("MASK", "ALLOW") else None,
        "reason_codes":   Reason_Codes,
        "latency_ms":     Latency_Ms,
    }

    Log_Request(Response)
    return Response


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------

@Application.get("/", response_model=Health_Response)
def Root():
    return {"Status": "Gateway running", "Version": "1.0.0"}


@Application.get("/Health", response_model=Health_Response)
def Health():
    return {"Status": "OK", "Version": "1.0.0"}


@Application.post("/Analyze")
def Analyze(Request_Data: Analyze_Request):
    """
    Main analysis endpoint.
    Accepts a text prompt and returns a full security analysis.
    """
    if not Request_Data.Text or not Request_Data.Text.strip():
        raise HTTPException(status_code=400, detail="Text field must not be empty.")

    Input_Id = Request_Data.Input_Id or f"req_{uuid.uuid4().hex[:8]}"
    return _Run_Pipeline(Request_Data.Text, Input_Id)


@Application.get("/Audit_Log")
def Get_Audit_Log(Last_N: int = 20):
    """Return the last N audit log entries."""
    return {"records": Read_Audit_Log(Last_N)}


@Application.post("/Retrain")
def Retrain():
    """Force retrain the semantic model (after adding new training data)."""
    Message = Retrain_Model()
    return {"message": Message}
