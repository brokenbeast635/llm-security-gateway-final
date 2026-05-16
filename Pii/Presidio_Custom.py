from presidio_analyzer import AnalyzerEngine, PatternRecognizer
from presidio_analyzer.pattern import Pattern
from presidio_analyzer.recognizer_result import RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from typing import List

# ---------------------------------------------------------------------------
# Presidio_Custom.py  –  Microsoft Presidio with local / contextual entities
# ---------------------------------------------------------------------------

# ------------------------------------------------------------------
# 1. Custom Pattern Recognizers
# ------------------------------------------------------------------

# Pakistani CNIC  e.g. 35202-1234567-1
Cnic_Pattern = Pattern(name="Cnic_Pattern", regex=r"\b\d{5}-\d{7}-\d\b", score=0.85)
Cnic_Recognizer = PatternRecognizer(
    supported_entity="CNIC",
    patterns=[Cnic_Pattern],
    context=["cnic", "national", "identity", "card", "id"],
)

# University student ID  e.g. FA21-BCS-123
Student_Id_Pattern = Pattern(
    name="Student_Id_Pattern",
    regex=r"\b[A-Z]{2}\d{2}-[A-Z]{3}-\d{3}\b",
    score=0.9,
)
Student_Id_Recognizer = PatternRecognizer(
    supported_entity="STUDENT_ID",
    patterns=[Student_Id_Pattern],
    context=["student", "registration", "rollno", "roll", "id"],
)

# Generic API key / token  (20+ alphanumeric/dash/underscore chars)
Api_Key_Pattern = Pattern(
    name="Api_Key_Pattern",
    regex=r"\b[A-Za-z0-9_\-]{20,}\b",
    score=0.6,
)
Api_Key_Recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[Api_Key_Pattern],
    context=["api", "key", "token", "secret", "bearer", "authorization"],
)

# Pakistani local phone  e.g. 0300-1234567 or 03001234567
Local_Phone_Pattern = Pattern(
    name="Local_Phone_Pattern",
    regex=r"\b0[3][0-9]{2}[-\s]?\d{7}\b",
    score=0.8,
)
Local_Phone_Recognizer = PatternRecognizer(
    supported_entity="PK_PHONE",
    patterns=[Local_Phone_Pattern],
    context=["phone", "cell", "mobile", "contact", "number"],
)

# ------------------------------------------------------------------
# 2. Analyzer + Anonymizer setup
# ------------------------------------------------------------------

Analyzer = AnalyzerEngine()
Analyzer.registry.add_recognizer(Cnic_Recognizer)
Analyzer.registry.add_recognizer(Student_Id_Recognizer)
Analyzer.registry.add_recognizer(Api_Key_Recognizer)
Analyzer.registry.add_recognizer(Local_Phone_Recognizer)

Anonymizer = AnonymizerEngine()

# Custom anonymization operators (clear placeholders)
Anonymizer_Operators = {
    "PERSON":         OperatorConfig("replace", {"new_value": "<PERSON>"}),
    "EMAIL_ADDRESS":  OperatorConfig("replace", {"new_value": "<EMAIL>"}),
    "PHONE_NUMBER":   OperatorConfig("replace", {"new_value": "<PHONE>"}),
    "PK_PHONE":       OperatorConfig("replace", {"new_value": "<PHONE>"}),
    "CNIC":           OperatorConfig("replace", {"new_value": "<CNIC>"}),
    "API_KEY":        OperatorConfig("replace", {"new_value": "<API_KEY>"}),
    "STUDENT_ID":     OperatorConfig("replace", {"new_value": "<STUDENT_ID>"}),
    "CREDIT_CARD":    OperatorConfig("replace", {"new_value": "<CREDIT_CARD>"}),
    "IBAN_CODE":      OperatorConfig("replace", {"new_value": "<IBAN>"}),
    "IP_ADDRESS":     OperatorConfig("replace", {"new_value": "<IP_ADDRESS>"}),
    "URL":            OperatorConfig("replace", {"new_value": "<URL>"}),
    "DEFAULT":        OperatorConfig("replace", {"new_value": "<REDACTED>"}),
}

# ------------------------------------------------------------------
# 3. Context-aware confidence boost
# ------------------------------------------------------------------

Context_Boost_Words = {
    "EMAIL_ADDRESS": ["email", "mail", "contact"],
    "PHONE_NUMBER":  ["phone", "cell", "mobile", "number"],
    "PK_PHONE":      ["phone", "cell", "mobile", "number"],
    "CNIC":          ["cnic", "national", "identity", "id"],
    "STUDENT_ID":    ["student", "registration", "roll"],
    "API_KEY":       ["api", "key", "token", "secret", "bearer"],
    "PERSON":        ["name", "person", "called", "mr", "ms", "dr"],
}


def _Boost_Scores(Text: str, Results: List[RecognizerResult]) -> List[RecognizerResult]:
    Text_Lower = Text.lower()
    Boosted = []
    for R in Results:
        Bonus = 0.0
        For_Entity = Context_Boost_Words.get(R.entity_type, [])
        for Word in For_Entity:
            if Word in Text_Lower:
                Bonus = 0.1
                break
        New_Score = min(R.score + Bonus, 1.0)
        Boosted.append(
            RecognizerResult(
                entity_type=R.entity_type,
                start=R.start,
                end=R.end,
                score=New_Score,
            )
        )
    return Boosted


# ------------------------------------------------------------------
# 4. Composite entity detection
# ------------------------------------------------------------------

def _Has_Composite(Results: List[RecognizerResult]) -> bool:
    """True if two or more distinct entity types are present together."""
    Types = {R.entity_type for R in Results}
    Pairs = [
        {"PERSON", "EMAIL_ADDRESS"},
        {"PERSON", "PHONE_NUMBER"},
        {"PERSON", "PK_PHONE"},
        {"STUDENT_ID", "EMAIL_ADDRESS"},
        {"CNIC", "PERSON"},
        {"API_KEY", "EMAIL_ADDRESS"},
    ]
    return any(P.issubset(Types) for P in Pairs)


# ------------------------------------------------------------------
# 5. Public API
# ------------------------------------------------------------------

def Analyze_Pii(Text: str, Min_Score: float = 0.4) -> tuple:
    """
    Analyze Text for PII entities.

    Returns:
        (Pii_Entities, Safe_Text, Has_Composite)

    Pii_Entities is a list of dicts:
        {"type": str, "text": str, "score": float}
    Safe_Text has all PII replaced with clear placeholders.
    Has_Composite is True when multiple PII types co-occur.
    """
    Raw_Results = Analyzer.analyze(text=Text, language="en")
    Boosted_Results = _Boost_Scores(Text, Raw_Results)
    Filtered = [R for R in Boosted_Results if R.score >= Min_Score]

    # Build entity list
    Pii_Entities = []
    for R in Filtered:
        Pii_Entities.append({
            "type": R.entity_type,
            "text": Text[R.start:R.end],
            "score": round(R.score, 3),
        })

    # Anonymize
    if Filtered:
        Anonymized = Anonymizer.anonymize(
            text=Text,
            analyzer_results=Filtered,
            operators=Anonymizer_Operators,
        )
        Safe_Text = Anonymized.text
    else:
        Safe_Text = Text

    Composite = _Has_Composite(Filtered)
    return Pii_Entities, Safe_Text, Composite
