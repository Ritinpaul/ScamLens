# ScamLens Friend Test Report

> **Testing Type:** Qualitative Non-Technical User Evaluation ("Build for a Friend" Validation)  
> **Privacy Notice:** In strict compliance with privacy guidelines, no personal identifiers, names, phone numbers, or private credentials are included. The participant is referenced anonymously.

---

## 1. Tester Profile
- **Identifier:** Friend Tester (Anonymous non-technical family member)
- **Technical Background:** Everyday smartphone and laptop user (WhatsApp, browsing, online shopping, mobile banking), with no cybersecurity, programming, or machine learning background.

---

## 2. Context
This user was selected because they represent the exact target demographic vulnerable to social engineering, utility cut-off panic, and courier fees: non-technical individuals who receive daily transactional SMS notifications and WhatsApp forwards, often struggling to discern whether an urgent security warning is genuine or an extortion attempt.

---

## 3. Procedure
The tester was seated in front of the live ScamLens local web application (`http://localhost:5173`) with minimal onboarding ("This is a privacy-first tool running locally on this laptop to help check if messages you receive are genuine or dangerous").

- Three demonstration messages from `data/friend_test/` were provided in plain text.
- **Blind Evaluation:** The tester was **not** informed of the expected classifications or technical indicators prior to testing.
- For each message, the tester followed the standard workflow:
  1. Read the message and shared what they initially thought they should do.
  2. Pasted the text into ScamLens and clicked **"Analyze Message"**.
  3. Observed the analysis screen and explained whether the verdict, explanation, and recommendations made sense.
  4. Answered the 6 qualitative evaluation questions.

---

| Test | Input Message Scenario | User's Initial Interpretation | ScamLens Initial Result | Resolved Result (Post-Fix) | User Understanding & Verdict Alignment |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Test 1: Technical Phishing** | SBI KYC account suspension threat with external link | "Looks scary because it says account suspended today. I would have felt panicked and clicked the link to check." | **SCAM** (High Confidence) | **SCAM** (High Confidence) | Understood immediately. The red banner and warning "Do NOT click links" made them realize the urgency was fabricated. |
| **Test 2: Semantic Social Engineering** | Family emergency asking for insurance password from friend's number | "I would have been worried, but suspicious because they said 'don't call'. I might have texted back asking who is Priya." | **SCAM** (Medium Confidence) | **SCAM** (Medium Confidence) | Understood. Noticed that ScamLens caught the "asking for password" and "urgency" even without any website link. |
| **Test 3: Legitimate Security Notification** | Routine login OTP notification with explicit "DO NOT share" warning | "This is just an OTP to log in. I would just enter the code on the login page." | **SCAM DETECTED** *(Bug exposed)* | **LIKELY LEGITIMATE** (Medium Confidence) | **Bug Caught by User:** Tester asked: *"Wait, why is it saying 'Do not share' is an action demanded by a scammer?"* After fixing the contextual calibration and server reload, user re-tested and agreed with the clear green shield. |

> [!IMPORTANT]
> **Real-World User Catch (Stage 5.1):** Test 3 was pivotal. In the initial live test, the running server had stale in-memory code and the model interpreted "Valid for 5 minutes" as urgency and "DO NOT share" as social engineering, outputting an erroneous `SCAM DETECTED` verdict. The non-technical tester immediately flagged this contradiction. This real-world catch directly triggered the Stage 5.1 contextual reasoning overhaul (distinguishing natural token expiry from coercive urgency, and negative security warnings from credential theft). Following the fix, the live UI was re-tested and accurately displayed `LIKELY LEGITIMATE`.

---

## 5. Qualitative Feedback

### Q1: Was it obvious what you were supposed to do?
> *"Yes, you just paste the message into the big box and press the analyze button. The big badge at the top makes it obvious right away whether it's safe or bad."*

### Q2: Did you understand why ScamLens marked the message as suspicious or safe?
> *"Yes. The explanation was in plain words. For the first one it clearly pointed out the fake link and the threat about account suspension. For the family one it highlighted that someone was asking for passwords."*

### Q3: Was anything confusing?
> *"The 'Evidence Trace' section at the bottom had some technical terms like 'normalized_length' and regex categories which I didn't really care about. I just focused on the top summary and the 'What Should I Do?' box."*

### Q4: Would you actually use this if you received a suspicious message?
> *"Yes, especially for weird SMS messages claiming electricity cutoffs or parcel customs fees that my relatives often forward on WhatsApp."*

### Q5: What would you change?
> *"A copy button for the recommendation, or a way to easily share a warning screenshot to WhatsApp so I can send it to my parents and say 'look, don't click this'."*

### Q6: Did the waiting time feel reasonable?
> *"It took around 30 seconds for each message. It was a bit long compared to regular apps, but because there was a loading animation saying 'Inspecting tactics locally', it felt like it was actually thinking and checking on the computer."*

---

## 6. Key Learnings & UX Insights
1. **The 'What Should I Do?' Action Card is Primary:** Non-technical users immediately seek concrete guidance ("Do not click", "Do not reply") rather than technical regex categories.
2. **Clear Polarity Reassures Users:** When legitimate OTPs are analyzed, displaying a clear green `Likely Legitimate` badge prevents security fatigue and prevents users from distrusting genuine bank alerts.
3. **Local Latency Framing:** While ~30s is slower than cloud APIs, communicating that the analysis is completely private and local without sending private messages to any external server makes the wait acceptable to privacy-conscious users.

---

## 7. Limitations & Honest Scope
- **Small-Scale Qualitative Feedback:** This evaluation reflects qualitative testing with an individual non-technical family member and is **not** an exhaustive statistical usability study across broad cohorts.
- **Assisted Environment:** The facilitator was present to launch the local servers (`FastAPI` + `Ollama`), meaning end-user setup friction was not evaluated in this test session.
