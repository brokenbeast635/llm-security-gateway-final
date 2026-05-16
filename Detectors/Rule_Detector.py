import re

# ---------------------------------------------------------------------------
# Rule_Detector.py  –  Fast pattern-based injection detector
# ---------------------------------------------------------------------------

Rule_Patterns = {
    "direct_injection": [
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions?",
        r"disregard\s+(all\s+)?(previous|prior|your)\s+instructions?",
        r"forget\s+(the\s+)?(earlier|previous|all)\s+(rules?|instructions?|guidelines?)",
        r"override\s+(your\s+)?(instructions?|rules?|policy|settings?)",
    ],
    "system_prompt_extraction": [
        r"reveal\s+(the\s+)?system\s+prompt",
        r"show\s+(the\s+|your\s+)?(hidden\s+)?(configuration|prompt|instructions?)",
        r"print\s+(your\s+)?(system\s+)?(prompt|instructions?)",
        r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|guidelines?)",
        r"display\s+(your\s+)?initial\s+(prompt|instructions?)",
    ],
    "jailbreak": [
        r"pretend\s+(you\s+are|to\s+be)\s+an?\s+(unrestricted|unfiltered|evil|jailbroken)",
        r"bypass\s+(all\s+)?(safety|security|content)\s+(rules?|filters?|guidelines?)",
        r"act\s+as\s+(if\s+)?(you\s+(have\s+)?no\s+restrictions?|dan|evil\s+gpt)",
        r"you\s+are\s+now\s+(dan|jailbroken|unrestricted|free\s+from)",
        r"enable\s+developer\s+mode",
        r"do\s+anything\s+now",
    ],
    "secret_extraction": [
        r"print\s+(any\s+)?(api\s+keys?|tokens?|passwords?|secrets?)",
        r"(share|leak|expose|reveal)\s+(your\s+)?(api\s+key|token|password|credentials?)",
        r"what\s+(is|are)\s+(the\s+)?(api\s+key|token|password|secret)",
    ],
    "rag_manipulation": [
        r"use\s+(the\s+)?retrieved\s+document\s+as\s+(a\s+)?system",
        r"treat\s+(this|the)\s+(document|context|input)\s+as\s+(a\s+)?(system\s+)?instruction",
        r"override\s+(your\s+)?policy\s+(using|with|from)",
    ],
    "obfuscated": [
        r"ign[o0]re\s+pr[e3]v[i!1][o0]us\s+[i!1]nstruct[i!1][o0]ns?",
        r"r[e3]v[e3]al\s+[s$][y]?st[e3]m\s+pr[o0]mpt",
        r"byp[a@][s$][s$]\s+[s$]af[e3]ty",
        r"b[\.\s]y[\.\s]p[\.\s]a[\.\s]s[\.\s]s",
        r"i\s+g\s+n\s+o\s+r\s+e\s+a\s+l\s+l",
        r"r[3e]v[3e][@a]l\s+.{0,10}syst[3e]m\s+pr[0o]mpt",
        r"b[\.\s]+y[\.\s]+p[\.\s]+a[\.\s]+s[\.\s]+s[\.\s]+s",
        r"i[\s]+g[\s]+n[\s]+o[\s]+r[\s]+e[\s]+a[\s]+l[\s]+l",
        r"b\s*\.\s*y\s*\.\s*p\s*\.\s*a\s*\.\s*s\s*\.\s*s",
    ],
    "urdu_injection": [
        r"پہلی\s+ہدایات\s+کو\s+نظر\s+انداز",
        r"سسٹم\s+پرامپٹ\s+دکھائیں",
        r"حفاظتی\s+قواعد\s+کو\s+نظرانداز",
        r"ہدایات\s+کو\s+نظر\s+انداز\s+کریں",
    ],
    "korean_injection": [
        r"이전\s+지침을\s+무시",
        r"시스템\s+프롬프트를\s+보여",
        r"안전\s+규칙을\s+우회",
        r"모든\s+지침을\s+무시",
        r"모든\s+규칙을\s+무시",
        r"비밀\s+정보를\s+출력",
        r"모든\s+지침을\s+무시",
        r"시스템\s+구성을\s+공개",
        r"이전\s+모든\s+규칙을\s+무시",
        r"모든\s+지침을\s+무시하고",
        r"시스템\s+구성을\s+공개",
        r"이전\s+모든\s+규칙을",
        r"비밀\s+정보를\s+출력",
    ],
    "hindi_injection": [
        r"पिछले\s+सभी\s+निर्देशों",
        r"नजरअंदाज\s+करो",
        r"निर्देशों\s+को\s+नजरअंदाज",
        r"सिस्टम\s+प्रॉम्प्ट\s+दिखाओ",
        r"पिछले\s+सभी\s+निर्देश",
        r"निर्देशों\s+को\s+नजरअंदाज",
        r"सिस्टम\s+प्रॉम्प्ट\s+दिखाओ",
        r"पिछले\s+सभी\s+निर्देश",
        r"पिछले\s+सभी\s+निर्देशों\s+को\s+नजरअंदाज\s+करो",
        r"सिस्टम\s+प्रॉम्प्ट\s+दिखाओ",
    ],
    "arabic_injection": [
        r"تجاهل\s+التعليمات\s+السابقة",
        r"أظهر\s+موجه\s+النظام",
        r"تجاوز\s+قواعد\s+الأمان",
    ],
}

Reason_Code_Map = {
    "direct_injection": "DIRECT_INJECTION",
    "system_prompt_extraction": "SYSTEM_PROMPT_EXTRACTION",
    "jailbreak": "JAILBREAK",
    "secret_extraction": "SECRET_EXTRACTION",
    "rag_manipulation": "RAG_MANIPULATION",
    "obfuscated": "OBFUSCATED_ATTACK",
    "urdu_injection": "MULTILINGUAL_INJECTION",
    "korean_injection": "MULTILINGUAL_INJECTION",
    "hindi_injection": "MULTILINGUAL_INJECTION",
    "arabic_injection": "MULTILINGUAL_INJECTION",
}


def Detect_Rule_Attack(Text: str) -> tuple[float, list[str]]:
    """
    Scan Text against all rule patterns.
    Returns (Score, Reason_Codes) where Score is in [0.0, 1.0].
    """
    Score = 0.0
    Reason_Codes = []
    Text_Lower = Text.lower()

    for Category, Patterns in Rule_Patterns.items():
        for Pattern in Patterns:
            if re.search(Pattern, Text_Lower, re.IGNORECASE | re.UNICODE):
                Score += 0.3
                Code = Reason_Code_Map.get(Category, "RULE_MATCH")
                if Code not in Reason_Codes:
                    Reason_Codes.append(Code)
                break  # one hit per category is enough

    return min(Score, 1.0), Reason_Codes
