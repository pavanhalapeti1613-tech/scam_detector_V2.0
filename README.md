# 🛡️ Scam Message Detector V2.0

A Python-based cybersecurity tool that analyzes emails and messages for potential **scam and phishing indicators**.

The project uses a **rule-based risk analysis engine** to examine message content, URLs, sender information, social-engineering patterns, suspicious keywords, and other indicators. It generates a risk score and explains why a message may be suspicious.

> ⚠️ **Disclaimer:** This project is an educational cybersecurity tool. A LOW risk score does not guarantee that a message is safe, and a HIGH risk score does not automatically prove that a message is fraudulent.

---

## 🚀 Features

### 🔍 Message Analysis

Analyzes the complete content of an email or message for suspicious patterns.

### 🚨 Suspicious Keyword Detection

Identifies potentially suspicious words and phrases commonly associated with phishing and scam attempts.

Examples include:

* Security-related terms
* Account-related terms
* Verification requests
* Urgency-related language
* Financial-related language

### 🔗 URL Intelligence

Extracts URLs from messages and analyzes them for suspicious characteristics.

The analyzer can identify indicators such as:

* Suspicious URL wording
* Account-related URL terms
* Security-related URL terms
* Potentially misleading links

### 👤 Sender Analysis

Analyzes the sender's email address and domain.

The sender analysis can detect:

* Sender email address
* Sender domain
* Free email providers
* Security/service-related terms in the sender address
* Unusually long numeric sequences
* Excessive special characters in the username

The analyzer prioritizes the email address associated with a `From` field rather than simply selecting the first email address found in the message.

### 🎭 Social Engineering Detection

Looks for psychological manipulation techniques such as:

* Urgency
* Authority impersonation
* Pressure to act
* Security-related warnings
* Requests for sensitive information

### 🏢 Brand Impersonation

Checks messages for potential impersonation of organizations or well-known services.

### 🕵️ Obfuscation Analysis

Looks for suspicious attempts to hide or disguise information inside messages.

### 📊 Risk Scoring

Combines detected indicators into an overall risk score.

The analyzer reports:

* Risk Score
* Risk Level
* Confidence
* Potential Attack Type
* Detected indicators
* Safety recommendations

### 📄 Detailed JSON Reports

The program can save a detailed analysis report in JSON format for further inspection or documentation.

---

# ⚙️ How It Works

The detector follows a multi-stage analysis process:

```text
Input Message
      │
      ▼
Message Extraction
      │
      ├───────────────┐
      ▼               ▼
Keyword Analysis   URL Analysis
      │               │
      ▼               ▼
Sender Analysis   URL Intelligence
      │
      ▼
Social Engineering Analysis
      │
      ▼
Brand Impersonation Analysis
      │
      ▼
Obfuscation Analysis
      │
      ▼
Risk Scoring
      │
      ▼
Risk Classification
      │
      ▼
Safety Recommendation
```

Each detection module contributes indicators to the overall analysis.

---

# 🧠 Detection Modules

| Module                   | Purpose                                       |
| ------------------------ | --------------------------------------------- |
| 🔍 Keyword Analysis      | Detects suspicious words and phrases          |
| 🔗 URL Intelligence      | Examines URLs for suspicious indicators       |
| 👤 Sender Analysis       | Analyzes sender email and domain              |
| 🎭 Social Engineering    | Detects manipulation and pressure tactics     |
| 🏢 Brand Impersonation   | Detects possible organization impersonation   |
| 🕵️ Obfuscation Analysis | Detects suspicious hiding/disguise techniques |
| 📊 Risk Scoring          | Calculates the overall risk                   |
| 📄 JSON Reporting        | Saves detailed analysis results               |

---

# 💻 Requirements

* Python 3.x
* `re`
* `json`
* Standard Python libraries used by the project

If your version of the project uses only Python's standard library, no external package installation is required.

---

# 📥 Installation

### 1. Clone the repository

```bash
git clone https://github.com/pavanhalapeti1613-tech/scam_detector_V2.0.git
```

### 2. Open the project directory

```bash
cd scam_detector_V2.0
```

### 3. Run the detector

```bash
python v2.0_scam_msg_detector.py
```

---

# ▶️ Usage

After starting the program, you will be asked to paste an email or message.

```text
Paste the email/message below.
Type END/end on a separate line when the message is finished.
```

Paste the complete message and type:

```text
END
```

on a separate line.

The program will then analyze the message and display the results.

---

# 🧪 Example Test

### Input

```text
Urgent: Your Bank Account Requires Verification

Dear Customer,

We detected unusual activity on your bank account.

To prevent your account from being suspended, verify your account immediately:

https://secure-bank-account-verification.example.com/login

Please confirm your account information within 24 hours.

From: Bank Security Team • security-alert9876@gmail.com
```

### Possible Indicators

```text
SUSPICIOUS KEYWORDS / PHRASES
• security
• verify
• urgent

URL INTELLIGENCE
• Suspicious URL indicators detected

SOCIAL ENGINEERING
• Urgency detected
• Possible authority impersonation

SENDER ANALYSIS
• Sender uses a free email provider
• Sender address contains security/service-related terms
• Sender contains an unusually long numeric sequence
```

The exact score depends on the indicators detected by the current version of the program.

---

# 📊 Example Output

```text
=================================================================
              ADVANCED PHISHING ANALYZER
=================================================================

Engine Version : 2.0
Risk Score     : XX/100
Risk Level     : MEDIUM
Confidence     : Medium
Attack Type    : Impersonation Phishing

-----------------------------------------------------------------
SENDER ANALYSIS
-----------------------------------------------------------------

Email  : security-alert9876@gmail.com
Domain : gmail.com

• Sender uses a free email provider: gmail.com
• Sender address contains security/service-related terms
• Sender address contains an unusually long numeric sequence
```

---

# 📈 Risk Interpretation

The risk score is intended as an **indicator**, not a guarantee.

| Risk Level | Meaning                                           |
| ---------- | ------------------------------------------------- |
| 🟢 LOW     | Few suspicious indicators detected                |
| 🟡 MEDIUM  | Several suspicious indicators detected            |
| 🔴 HIGH    | Multiple strong phishing/scam indicators detected |

A message should always be evaluated using context and common-sense security practices.

---

# 🛡️ Safety Recommendations

When a message appears suspicious:

* Do not provide passwords or verification codes.
* Avoid clicking suspicious links.
* Verify the sender using an independent method.
* Do not make financial decisions based solely on the message.
* Check the organization's official website or application directly.
* Treat unexpected urgent requests with caution.

---

# 📁 Project Structure

```text
scam_detector_V2.0/
│
├── v2.0_scam_msg_detector.py
├── README.md
└── reports/
    └── analysis_report.json
```

> The `reports` folder is created/used if JSON report saving is enabled in your local version.

---

# 🔄 Version 2.0 Improvements

Compared with a basic keyword-based message checker, V2.0 expands the analysis into multiple security dimensions:

* Improved sender identification
* Sender domain analysis
* Free email provider detection
* Suspicious sender terminology detection
* Numeric-pattern detection in sender addresses
* Special-character analysis
* URL intelligence
* Social-engineering analysis
* Brand impersonation analysis
* Obfuscation analysis
* Risk scoring
* Confidence estimation
* Attack-type classification
* Detailed safety recommendations
* Optional JSON reporting

---

# 🎯 Project Goals

The main goals of this project are to:

1. Improve awareness of phishing and scam messages.
2. Demonstrate rule-based cybersecurity analysis.
3. Explain why a message may be suspicious.
4. Provide a structured risk assessment.
5. Help students understand practical phishing-detection techniques.
6. Provide a foundation for future cybersecurity improvements.

---

# 🔮 Future Improvements

Possible future versions could include:

* Machine-learning-based classification
* Natural Language Processing (NLP)
* Domain reputation checking
* Email-header analysis
* QR-code analysis
* Attachment analysis
* Screenshot/OCR analysis
* Multilingual scam detection
* Threat-intelligence integration
* Web-based interface
* Real-time email analysis
* Improved false-positive handling

---

# ⚠️ Limitations

This project is based primarily on **rule-based detection**.

Therefore:

* Legitimate messages may sometimes be flagged.
* Sophisticated scams may avoid detection.
* A LOW score does not prove that a message is safe.
* A HIGH score does not independently prove that a message is fraudulent.
* Sender analysis depends on how sender information is represented in the input.
* The tool should not replace professional cybersecurity or financial advice.

---

# 🔐 Security Note

Never paste real passwords, authentication codes, banking credentials, API keys, or other sensitive information into a testing environment.

For testing, use fictional or sanitized messages.

---

# 👨‍💻 Author

**Pavan Halapeti, ECE student, Dr. Ambedkar institute of technology banglore-560056**

GitHub:
https://github.com/pavanhalapeti1613-tech

---

# ⭐ Project

If you find this project useful for learning cybersecurity, consider giving the repository a ⭐ on GitHub.

**Repository:**
https://github.com/pavanhalapeti1613-tech/scam_detector_V2.0

---

## 📜 License

This project is intended for educational and cybersecurity-awareness purposes.

