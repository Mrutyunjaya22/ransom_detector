# 📁 Ready-to-Use Demo Samples for File Upload & Panel Presentation

Use these sample files to test the **File Inspector** feature in the web dashboard (**http://localhost:8081/**):

| File Name | Type | Expected Entropy | Expected Verdict | Notes |
|---|---|---|---|---|
| **`clean_audit_report.txt`** | Benign Document | $\approx 4.6$ bits/byte | **CLEAN (0.000)** | Standard corporate text report. |
| **`clean_employee_roster.csv`** | Benign Structured Data | $\approx 3.9$ bits/byte | **CLEAN (0.000)** | Plaintext comma-separated values. |
| **`financial_data.xlsx.locked`** | Ransomware Encrypted Artifact | $\approx 7.99$ bits/byte | **MALICIOUS (1.000)** | Simulated LockBit-style encrypted payload with high Shannon entropy & `.locked` extension. |
| **`customer_database.db.crypto`** | Ransomware Encrypted Binary | $\approx 7.98$ bits/byte | **MALICIOUS (1.000)** | Simulated cryptolocker binary dump with high entropy & `.crypto` extension. |

---

### How to Test during Panel Demo:
1. Open the **File Inspector** tab at `http://localhost:8081/`.
2. Click **`Choose files`** and select any file from this folder (`demo_samples/`), OR drag & drop them directly into the dashed box.
3. *Alternative*: Use the built-in **`[📄 Test Clean Sample]`** or **`[🚨 Test Ransomware Sample]`** instant buttons on the UI!
