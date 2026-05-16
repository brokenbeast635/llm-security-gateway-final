import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from Policy.Policy_Engine import Decide_Policy

# ---------------------------------------------------------------------------
# Tests/Test_Policy.py  –  Unit tests for the policy engine
# ---------------------------------------------------------------------------

def Test_Allow_Safe_Prompt():
    Result = Decide_Policy(0.0, 0.05, [], False, [])
    assert Result["decision"] == "ALLOW", f"Expected ALLOW, got {Result['decision']}"
    print("PASS  Test_Allow_Safe_Prompt")

def Test_Block_High_Rule_Score():
    Result = Decide_Policy(0.8, 0.1, [], False, ["DIRECT_INJECTION"])
    assert Result["decision"] == "BLOCK", f"Expected BLOCK, got {Result['decision']}"
    print("PASS  Test_Block_High_Rule_Score")

def Test_Block_High_Semantic_Score():
    Result = Decide_Policy(0.0, 0.9, [], False, [])
    assert Result["decision"] == "BLOCK", f"Expected BLOCK, got {Result['decision']}"
    print("PASS  Test_Block_High_Semantic_Score")

def Test_Mask_Pii_Present():
    Pii = [{"type": "EMAIL_ADDRESS", "text": "a@b.com", "score": 0.95}]
    Result = Decide_Policy(0.0, 0.05, Pii, False, [])
    assert Result["decision"] == "MASK", f"Expected MASK, got {Result['decision']}"
    print("PASS  Test_Mask_Pii_Present")

def Test_Block_With_Pii_And_High_Score():
    Pii = [{"type": "EMAIL_ADDRESS", "text": "a@b.com", "score": 0.95}]
    Result = Decide_Policy(0.8, 0.85, Pii, False, ["DIRECT_INJECTION"])
    assert Result["decision"] == "BLOCK", f"Expected BLOCK, got {Result['decision']}"
    print("PASS  Test_Block_With_Pii_And_High_Score")

def Test_Reason_Codes_Populated():
    Result = Decide_Policy(0.4, 0.8, [], False, ["DIRECT_INJECTION"])
    assert "SEMANTIC_INJECTION" in Result["reason_codes"]
    assert "DIRECT_INJECTION" in Result["reason_codes"]
    print("PASS  Test_Reason_Codes_Populated")

if __name__ == "__main__":
    Test_Allow_Safe_Prompt()
    Test_Block_High_Rule_Score()
    Test_Block_High_Semantic_Score()
    Test_Mask_Pii_Present()
    Test_Block_With_Pii_And_High_Score()
    Test_Reason_Codes_Populated()
    print("\nAll policy tests passed.")
