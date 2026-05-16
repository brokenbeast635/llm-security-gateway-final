import sys
import os
import json
import time
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from Detectors.Rule_Detector import Detect_Rule_Attack
from Detectors.Semantic_Detector import Semantic_Score
from Utils.Language import Detect_Language, Is_Multilingual
from Pii.Presidio_Custom import Analyze_Pii
from Policy.Policy_Engine import Decide_Policy

# ---------------------------------------------------------------------------
# Run_Evaluation.py  –  Full reproducible evaluation of the security gateway
# ---------------------------------------------------------------------------

Eval_Csv_Path    = "Data/Final_Eval.csv"
Results_Dir      = "Results"
Results_Csv_Path = "Results/Evaluation_Results.csv"
Metrics_Path     = "Results/Metrics_Summary.json"


# ------------------------------------------------------------------
# Helper: map expected_policy to binary label (BLOCK=1, else=0)
# ------------------------------------------------------------------

def _Policy_To_Binary(Policy: str) -> int:
    return 1 if str(Policy).strip().upper() == "BLOCK" else 0


def _Decision_To_Binary(Decision: str) -> int:
    return 1 if str(Decision).strip().upper() == "BLOCK" else 0


# ------------------------------------------------------------------
# Rule-only pipeline (baseline)
# ------------------------------------------------------------------

def Run_Rule_Only(Text: str) -> str:
    Rule_Score, _ = Detect_Rule_Attack(Text)
    return "BLOCK" if Rule_Score >= 0.4 else "ALLOW"


# ------------------------------------------------------------------
# Hybrid pipeline (full system)
# ------------------------------------------------------------------

def Run_Hybrid(Text: str) -> dict:
    Start = time.time()
    Rule_Score, Rule_Codes = Detect_Rule_Attack(Text)
    Sem_Score = Semantic_Score(Text)
    Pii_Entities, Safe_Text, Has_Composite = Analyze_Pii(Text)
    Policy = Decide_Policy(
        Rule_Score=Rule_Score,
        Semantic_Score_Value=Sem_Score,
        Pii_Entities=Pii_Entities,
        Has_Composite=Has_Composite,
        Rule_Reason_Codes=Rule_Codes,
    )
    Latency = round((time.time() - Start) * 1000, 2)
    return {
        "rule_score": round(Rule_Score, 4),
        "semantic_score": round(Sem_Score, 4),
        "pii_count": len(Pii_Entities),
        "decision": Policy["decision"],
        "final_risk": Policy["final_risk"],
        "reason_codes": "|".join(Policy["reason_codes"]),
        "latency_ms": Latency,
    }


# ------------------------------------------------------------------
# Main evaluation loop
# ------------------------------------------------------------------

def Evaluate():
    os.makedirs(Results_Dir, exist_ok=True)

    print(f"\n{'='*60}")
    print("  LLM Security Gateway – Evaluation Report")
    print(f"{'='*60}\n")

    Df = pd.read_csv(Eval_Csv_Path)
    print(f"Dataset loaded: {len(Df)} rows\n")

    # ---- Dataset summary ----
    print("[ Dataset Summary ]")
    print(f"  Total prompts       : {len(Df)}")
    print(f"  Benign (ALLOW)      : {(Df['expected_policy']=='ALLOW').sum()}")
    print(f"  Mask (MASK)         : {(Df['expected_policy']=='MASK').sum()}")
    print(f"  Attack (BLOCK)      : {(Df['expected_policy']=='BLOCK').sum()}")
    print(f"  With PII            : {Df['has_pii'].sum()}")
    Lang_Counts = Df['language'].value_counts()
    print(f"  Languages           : {dict(Lang_Counts)}\n")

    # ---- Run both pipelines ----
    Rule_Predictions     = []
    Hybrid_Decisions     = []
    Hybrid_Rule_Scores   = []
    Hybrid_Sem_Scores    = []
    Hybrid_Final_Risks   = []
    Hybrid_Pii_Counts    = []
    Hybrid_Reason_Codes  = []
    Latency_List         = []
    Expected_Labels      = []

    print("Running evaluation (this may take a moment)...")
    for _, Row in Df.iterrows():
        Text = str(Row["prompt"])
        Expected_Labels.append(_Policy_To_Binary(Row["expected_policy"]))

        Rule_Only_Decision = Run_Rule_Only(Text)
        Rule_Predictions.append(_Decision_To_Binary(Rule_Only_Decision))

        Hybrid_Result = Run_Hybrid(Text)
        Hybrid_Decisions.append(_Decision_To_Binary(Hybrid_Result["decision"]))
        Hybrid_Rule_Scores.append(Hybrid_Result["rule_score"])
        Hybrid_Sem_Scores.append(Hybrid_Result["semantic_score"])
        Hybrid_Final_Risks.append(Hybrid_Result["final_risk"])
        Hybrid_Pii_Counts.append(Hybrid_Result["pii_count"])
        Hybrid_Reason_Codes.append(Hybrid_Result["reason_codes"])
        Latency_List.append(Hybrid_Result["latency_ms"])

    # ---- Save full results CSV ----
    Result_Df = Df.copy()
    Result_Df["rule_only_decision"] = ["BLOCK" if P else "ALLOW" for P in Rule_Predictions]
    Result_Df["hybrid_decision"]    = ["BLOCK" if P else "ALLOW" for P in Hybrid_Decisions]
    Result_Df["rule_score"]         = Hybrid_Rule_Scores
    Result_Df["semantic_score"]     = Hybrid_Sem_Scores
    Result_Df["final_risk"]         = Hybrid_Final_Risks
    Result_Df["pii_count"]          = Hybrid_Pii_Counts
    Result_Df["reason_codes"]       = Hybrid_Reason_Codes
    Result_Df["latency_ms"]         = Latency_List
    Result_Df.to_csv(Results_Csv_Path, index=False)
    print(f"Results saved to {Results_Csv_Path}\n")

    # ---- Compute metrics ----
    def Compute_Metrics(Y_True, Y_Pred, Name):
        Acc  = accuracy_score(Y_True, Y_Pred)
        Prec = precision_score(Y_True, Y_Pred, zero_division=0)
        Rec  = recall_score(Y_True, Y_Pred, zero_division=0)
        F1   = f1_score(Y_True, Y_Pred, zero_division=0)
        Cm   = confusion_matrix(Y_True, Y_Pred)
        TN, FP, FN, TP = Cm.ravel() if Cm.shape == (2, 2) else (0, 0, 0, 0)
        return {
            "name": Name,
            "accuracy": round(Acc, 4),
            "precision": round(Prec, 4),
            "recall": round(Rec, 4),
            "f1": round(F1, 4),
            "true_positives": int(TP),
            "true_negatives": int(TN),
            "false_positives": int(FP),
            "false_negatives": int(FN),
        }

    Rule_Metrics   = Compute_Metrics(Expected_Labels, Rule_Predictions, "Rule_Only")
    Hybrid_Metrics = Compute_Metrics(Expected_Labels, Hybrid_Decisions, "Hybrid")

    # ---- Print comparison table ----
    print("[ Rule-Only vs Hybrid Metrics Table ]")
    Header = f"{'Metric':<20} {'Rule_Only':>12} {'Hybrid':>12}"
    print(Header)
    print("-" * len(Header))
    for Key in ["accuracy", "precision", "recall", "f1",
                "true_positives", "false_positives", "false_negatives"]:
        print(f"{Key:<20} {Rule_Metrics[Key]:>12} {Hybrid_Metrics[Key]:>12}")
    print()

    # ---- Per-language robustness ----
    print("[ Multilingual Robustness Table ]")
    print(f"{'Language':<12} {'Total':>7} {'Correct':>9} {'Recall':>8}")
    print("-" * 40)
    for Lang in Df["language"].unique():
        Lang_Idx = Df["language"] == Lang
        Lang_True = [Expected_Labels[i] for i, v in enumerate(Lang_Idx) if v]
        Lang_Pred = [Hybrid_Decisions[i] for i, v in enumerate(Lang_Idx) if v]
        if not Lang_True:
            continue
        Correct = sum(t == p for t, p in zip(Lang_True, Lang_Pred))
        Total   = len(Lang_True)
        Attack_True = [t for t in Lang_True if t == 1]
        Attack_Pred = [p for t, p in zip(Lang_True, Lang_Pred) if t == 1]
        Lang_Recall = sum(t == p for t, p in zip(Attack_True, Attack_Pred)) / max(len(Attack_True), 1)
        print(f"{Lang:<12} {Total:>7} {Correct:>9} {Lang_Recall:>8.2f}")
    print()

    # ---- Latency table ----
    Lat_Array = np.array(Latency_List)
    print("[ Latency Summary (Hybrid Mode) ]")
    print(f"  Mean   : {Lat_Array.mean():.2f} ms")
    print(f"  Median : {np.median(Lat_Array):.2f} ms")
    print(f"  p95    : {np.percentile(Lat_Array, 95):.2f} ms")
    print(f"  Max    : {Lat_Array.max():.2f} ms\n")

    # ---- Error analysis ----
    Errors = Result_Df[
        Result_Df["expected_policy"].apply(_Policy_To_Binary) !=
        Result_Df["hybrid_decision"].apply(_Decision_To_Binary)
    ]
    print(f"[ Error Analysis ] – {len(Errors)} misclassified cases")
    if not Errors.empty:
        for _, E in Errors.iterrows():
            print(f"  ID: {E['id']} | Expected: {E['expected_policy']} "
                  f"| Got: {E['hybrid_decision']} | Type: {E['attack_type']}")
            print(f"    Prompt: {str(E['prompt'])[:80]}...")
    print()

    # ---- Save metrics JSON ----
    Metrics_Summary = {
        "rule_only": Rule_Metrics,
        "hybrid": Hybrid_Metrics,
        "latency": {
            "mean_ms":   round(float(Lat_Array.mean()), 2),
            "median_ms": round(float(np.median(Lat_Array)), 2),
            "p95_ms":    round(float(np.percentile(Lat_Array, 95)), 2),
            "max_ms":    round(float(Lat_Array.max()), 2),
        },
        "dataset": {
            "total": len(Df),
            "benign": int((Df["expected_policy"] == "ALLOW").sum()),
            "mask": int((Df["expected_policy"] == "MASK").sum()),
            "attack": int((Df["expected_policy"] == "BLOCK").sum()),
            "errors": len(Errors),
        },
    }
    with open(Metrics_Path, "w") as F:
        json.dump(Metrics_Summary, F, indent=2)
    print(f"Metrics saved to {Metrics_Path}")
    print(f"\n{'='*60}\n  Evaluation complete.\n{'='*60}\n")


if __name__ == "__main__":
    Evaluate()
