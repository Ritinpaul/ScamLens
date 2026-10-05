# ScamLens Friend Test Pack 🧪

> **Demonstration and Test Inputs Only**  
> These messages are provided strictly for qualitative user-testing with non-technical friends and family members.  
> They contain **no real credentials, no real personal details, no active malicious domains, and no operational URLs**.

---

## Instructions for the Facilitator

1. Provide the tester access to the ScamLens web interface at `http://localhost:5173`.
2. Do **NOT** tell the tester what the expected outcome is or whether each message is a scam.
3. Have the tester copy/paste one message at a time into ScamLens.
4. Observe their immediate reaction, understanding, and decisions.

---

## Test Messages

### Test 1: Technical Phishing (`test_01_technical_phishing.txt`)
**Scenario:** High-urgency bank KYC phishing utilizing urgency threats, credential solicitation, and an impersonated link.  
**Message Text:**
```
Dear Customer, your SBI NetBanking account will be suspended today due to KYC failure. Verify your PAN and login password immediately at http://sbi-kyc-verify.example.com/login to prevent permanent blockage.
```
- **Expected Outcome:** `SCAM` (Confidence: High)
- **Primary Mechanism:** Caught by both deterministic signatures (mismatched banking domain, credential solicitation, urgency) and AI semantic understanding.

---

### Test 2: Semantic Social Engineering (`test_02_social_engineering.txt`)
**Scenario:** Family emergency impersonation asking for sensitive credentials with NO URLs, NO banking words, and NO payment amounts.  
**Message Text:**
```
Hi, my phone broke and fell in water so I am texting from my friend's number. Can you send me the family password for our insurance portal urgently? Please don't call right now because I am in class.
```
- **Expected Outcome:** `SCAM` (Confidence: Medium)
- **Primary Mechanism:** Detected exclusively by AI semantic reasoning (emotional pressure, impersonation pretext, avoiding phone calls, credential extraction). Proves why the AI layer is necessary.

---

### Test 3: Legitimate Security Notification (`test_03_legitimate_otp.txt`)
**Scenario:** Routine transactional authentication code delivery with an explicit protective security notice.  
**Message Text:**
```
Your login OTP is 482913. Valid for 5 minutes. DO NOT share this OTP with anyone, including bank employees or support agents. If you did not request this login, review your account security settings.
```
- **Expected Outcome:** `LIKELY LEGITIMATE` (Confidence: Medium)
- **Primary Mechanism:** Contextual calibration correctly recognizes the protective warning ("DO NOT share") as legitimate, rather than misclassifying it as a credential-theft attempt.
