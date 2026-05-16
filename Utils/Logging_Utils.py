import json
import os
import logging
from datetime import datetime

# ---------------------------------------------------------------------------
# Logging_Utils.py  –  Audit logger for every gateway request
# ---------------------------------------------------------------------------

Audit_Log_Path = "Results/Audit_Log.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

Logger = logging.getLogger("Llm_Security_Gateway")


def Log_Request(Data: dict) -> None:
    """
    Append one JSON record to the audit log.
    Adds a UTC timestamp automatically.
    """
    os.makedirs(os.path.dirname(Audit_Log_Path), exist_ok=True)
    Record = {"timestamp": datetime.utcnow().isoformat() + "Z", **Data}
    with open(Audit_Log_Path, "a", encoding="utf-8") as File:
        File.write(json.dumps(Record, ensure_ascii=False) + "\n")
    Logger.info(
        "Request logged | id=%s decision=%s latency=%.1fms",
        Data.get("input_id", "-"),
        Data.get("decision", "-"),
        Data.get("latency_ms", 0),
    )


def Read_Audit_Log(Last_N: int = 10) -> list:
    """Return the last N records from the audit log."""
    if not os.path.exists(Audit_Log_Path):
        return []
    with open(Audit_Log_Path, "r", encoding="utf-8") as File:
        Lines = File.readlines()
    Records = []
    for Line in Lines[-Last_N:]:
        try:
            Records.append(json.loads(Line))
        except json.JSONDecodeError:
            pass
    return Records
