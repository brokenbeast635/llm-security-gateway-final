from langdetect import detect, DetectorFactory

# ---------------------------------------------------------------------------
# Language.py  –  Wrapper around langdetect for stable language detection
# ---------------------------------------------------------------------------

# Fix seed for reproducibility
DetectorFactory.seed = 42

Language_Name_Map = {
    "en": "English",
    "ur": "Urdu",
    "ko": "Korean",
    "ar": "Arabic",
    "hi": "Hindi",
    "ro": "Roman Urdu (approximated)",
    "unknown": "Unknown",
}


def Detect_Language(Text: str) -> str:
    """
    Detect the primary language of Text.
    Returns an ISO 639-1 language code or 'unknown'.
    """
    try:
        if not Text or len(Text.strip()) < 3:
            return "unknown"
        return detect(Text)
    except Exception:
        return "unknown"


def Get_Language_Name(Code: str) -> str:
    """Return a human-readable name for the given ISO language code."""
    return Language_Name_Map.get(Code, Code)


def Is_Multilingual(Text: str) -> bool:
    """
    Heuristic check: True if the text mixes scripts (Latin + non-Latin).
    Useful for flagging mixed-language attacks.
    """
    Has_Latin = any(ord(Ch) < 128 and Ch.isalpha() for Ch in Text)
    Has_Non_Latin = any(ord(Ch) > 127 for Ch in Text)
    return Has_Latin and Has_Non_Latin
