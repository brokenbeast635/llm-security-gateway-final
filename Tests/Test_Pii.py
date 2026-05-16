import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from Pii.Presidio_Custom import Analyze_Pii

# ---------------------------------------------------------------------------
# Tests/Test_Pii.py  –  Unit tests for Presidio PII detection
# ---------------------------------------------------------------------------

def _Entity_Types(Entities):
    return {E["type"] for E in Entities}

def Test_Email_Detected():
    Entities, Safe_Text, _ = Analyze_Pii("Send it to ali@example.com please.")
    assert "EMAIL_ADDRESS" in _Entity_Types(Entities), "EMAIL_ADDRESS not found"
    assert "<EMAIL>" in Safe_Text, "Email not masked"
    print("PASS  Test_Email_Detected")

def Test_Cnic_Detected():
    Entities, Safe_Text, _ = Analyze_Pii("My CNIC is 35202-1234567-1.")
    assert "CNIC" in _Entity_Types(Entities), "CNIC not found"
    assert "<CNIC>" in Safe_Text, "CNIC not masked"
    print("PASS  Test_Cnic_Detected")

def Test_Student_Id_Detected():
    Entities, Safe_Text, _ = Analyze_Pii("My student ID is FA21-BCS-123.")
    assert "STUDENT_ID" in _Entity_Types(Entities), "STUDENT_ID not found"
    assert "<STUDENT_ID>" in Safe_Text, "Student ID not masked"
    print("PASS  Test_Student_Id_Detected")

def Test_Pk_Phone_Detected():
    Entities, Safe_Text, _ = Analyze_Pii("My phone number is 0300-1234567.")
    Types = _Entity_Types(Entities)
    Has_Phone = "PK_PHONE" in Types or "PHONE_NUMBER" in Types
    assert Has_Phone, f"No phone entity found. Got: {Types}"
    print("PASS  Test_Pk_Phone_Detected")

def Test_Composite_Pii():
    Entities, _, Has_Composite = Analyze_Pii(
        "My name is Ahmed and email is ahmed@uni.edu."
    )
    Types = _Entity_Types(Entities)
    assert "EMAIL_ADDRESS" in Types, "EMAIL_ADDRESS missing in composite"
    print("PASS  Test_Composite_Pii")

def Test_No_Pii_Clean():
    Entities, Safe_Text, _ = Analyze_Pii("Explain how gradient descent works in neural networks.")
    Filtered = [E for E in Entities if E["score"] >= 0.7]
    assert len(Filtered) == 0, f"Unexpected PII found: {Filtered}"
    print("PASS  Test_No_Pii_Clean")

if __name__ == "__main__":
    Test_Email_Detected()
    Test_Cnic_Detected()
    Test_Student_Id_Detected()
    Test_Pk_Phone_Detected()
    Test_Composite_Pii()
    Test_No_Pii_Clean()
    print("\nAll PII tests passed.")
