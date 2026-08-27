import re
import json
import math
from datetime import datetime
from urllib.parse import urlparse, unquote


# =====================================================
# PHISHING MESSAGE IDENTIFIER - VERSION 2.0
# =====================================================

VERSION = "2.0"


# =========================================
# 1. SUSPICIOUS PHRASES
# =========================================

SUSPICIOUS_PHRASES = {
    "act now": 5,
    "act immediately": 5,
    "urgent action required": 7,
    "immediate action required": 7,
    "respond immediately": 5,
    "within 24 hours": 5,
    "within 48 hours": 4,
    "limited time": 4,
    "do this now": 5,
    "don't delay": 5,

    "account suspended": 8,
    "account will be suspended": 9,
    "account blocked": 8,
    "account has been locked": 8,
    "account will be closed": 8,
    "access will be revoked": 7,

    "verify your account": 7,
    "verify your identity": 6,
    "confirm your identity": 6,
    "confirm your account": 7,
    "verify your information": 6,
    "update your account": 5,
    "update your information": 5,

    "enter your password": 9,
    "provide your password": 9,
    "confirm your password": 9,
    "enter your username": 7,
    "enter your login details": 9,
    "verify your login": 7,
    "login credentials": 8,

    "enter your otp": 10,
    "provide your otp": 10,
    "share your otp": 10,
    "one time password": 7,
    "verification code": 6,

    "credit card number": 9,
    "debit card number": 9,
    "bank account number": 9,
    "card details": 8,
    "bank details": 8,
    "payment information": 7,

    "you have won": 7,
    "you are a winner": 7,
    "claim your prize": 8,
    "claim your reward": 7,
    "free gift": 5,
    "lottery winner": 8,
    "congratulations you won": 8,

    "legal action": 7,
    "police action": 8,
    "account violation": 6,
    "security breach": 6,
    "unauthorized activity": 6,
    "suspicious activity": 5,

    "click the link": 5,
    "click here": 4,
    "download now": 5,
    "login now": 6,
    "verify now": 6
}


# ===================================
# 2. SUSPICIOUS KEYWORDS
# ===================================
SUSPICIOUS_KEYWORDS = {
    "urgent": 3,
    "immediately": 3,
    "warning": 3,
    "alert": 3,
    "suspended": 5,
    "blocked": 5,
    "locked": 5,
    "verify": 3,
    "verification": 3,
    "confirm": 2,
    "password": 5,
    "username": 4,
    "login": 3,
    "credential": 6,
    "otp": 8,
    "payment": 4,
    "bank": 3,
    "refund": 4,
    "invoice": 3,
    "security": 2,
    "winner": 5,
    "prize": 5,
    "reward": 4,
    "lottery": 6,
    "claim": 3,
    "click": 2,
    "download": 3,
    "attachment": 2,
    "limited": 3,
    "expires": 4,
    "expire": 4,
    "penalty": 5,
    "fine": 4,
    "legal": 4,
    "action": 2
}


# ====================================
# 3. URL INTELLIGENCE
# ====================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "shorturl.at",
    "cutt.ly",
    "rb.gy"
}


SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".zip",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq"
}


URL_SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "password",
    "payment",
    "confirm",
    "wallet",
    "bank",
    "authenticate"
}


def extract_urls(message):
    """
    Extract HTTP/HTTPS URLs.
    """
    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, message)


def is_ip_address(domain):
    """
    Detect IPv4 addresses.
    """
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if not re.match(pattern, domain):
        return False

    parts = domain.split(".")

    return all(0 <= int(part) <= 255 for part in parts)


def calculate_entropy(text):
    """
    Calculate Shannon entropy.
    Higher entropy can indicate heavily encoded/obfuscated strings.
    """
    if not text:
        return 0

    probabilities = [
        text.count(char) / len(text)
        for char in set(text)
    ]

    return -sum(
        probability * math.log2(probability)
        for probability in probabilities
    )


def analyze_urls(urls):

    results = []
    total_score = 0

    for url in urls:

        reasons = []
        indicators = []
        score = 0

        try:

            decoded_url = unquote(url)
            parsed = urlparse(url)

            domain = parsed.netloc.lower()

            # Remove username/password and port
            domain = domain.split("@")[-1]
            domain = domain.split(":")[0]

            # ------------------------------------------------
            # HTTPS CHECK
            # ------------------------------------------------

            if parsed.scheme.lower() == "http":
                reasons.append("Uses HTTP instead of HTTPS.")
                indicators.append("HTTP")
                score += 5


            # ------------------------------------------------
            # IP ADDRESS CHECK
            # ------------------------------------------------

            if is_ip_address(domain):

                reasons.append(
                    "Uses an IP address instead of a domain name."
                )

                indicators.append("IP_ADDRESS")
                score += 10


            # ------------------------------------------------
            # URL SHORTENER
            # ------------------------------------------------

            if domain in URL_SHORTENERS:

                reasons.append(
                    "Uses a known URL shortening service."
                )

                indicators.append("URL_SHORTENER")
                score += 7


            # ------------------------------------------------
            # SUSPICIOUS TLD
            # ------------------------------------------------

            for tld in SUSPICIOUS_TLDS:

                if domain.endswith(tld):

                    reasons.append(
                        f"Uses potentially suspicious TLD: {tld}"
                    )

                    indicators.append("SUSPICIOUS_TLD")
                    score += 6

                    break


            # ------------------------------------------------
            # EXCESSIVE SUBDOMAINS
            # ------------------------------------------------

            subdomain_count = domain.count(".")

            if subdomain_count >= 3:

                reasons.append(
                    "Contains an unusually large number of subdomains."
                )

                indicators.append("EXCESSIVE_SUBDOMAINS")
                score += 5


            # ------------------------------------------------
            # MULTIPLE HYPHENS
            # ------------------------------------------------

            if domain.count("-") >= 2:

                reasons.append(
                    "Domain contains multiple hyphens."
                )

                indicators.append("MULTIPLE_HYPHENS")
                score += 4


            # ------------------------------------------------
            # LONG URL
            # ------------------------------------------------

            if len(url) > 100:

                reasons.append(
                    "URL is unusually long."
                )

                indicators.append("LONG_URL")
                score += 4


            # ------------------------------------------------
            # @ SYMBOL
            # ------------------------------------------------

            if "@" in url:

                reasons.append(
                    "URL contains an @ symbol that may obscure the destination."
                )

                indicators.append("AT_SYMBOL")
                score += 10


            # ------------------------------------------------
            # SUSPICIOUS WORDS
            # ------------------------------------------------

            found_words = [
                word
                for word in URL_SUSPICIOUS_WORDS
                if word in decoded_url.lower()
            ]

            if found_words:

                reasons.append(
                    "Contains security/account-related URL terms: "
                    + ", ".join(found_words)
                )

                indicators.append("SUSPICIOUS_URL_WORDS")
                score += min(len(found_words) * 2, 10)


            # ------------------------------------------------
            # ENCODED CHARACTERS
            # ------------------------------------------------

            if "%" in url:

                reasons.append(
                    "Contains encoded URL characters."
                )

                indicators.append("ENCODED_URL")
                score += 3


            # ------------------------------------------------
            # PUNYCODE
            # ------------------------------------------------

            if "xn--" in domain:

                reasons.append(
                    "Uses a Punycode/IDN domain that requires additional verification."
                )

                indicators.append("PUNYCODE")
                score += 8


            # ------------------------------------------------
            # DOUBLE SLASH IN PATH
            # ------------------------------------------------

            if "//" in parsed.path:

                reasons.append(
                    "Contains unusual double-slash path structure."
                )

                indicators.append("DOUBLE_SLASH")
                score += 3


            # ------------------------------------------------
            # HIGH ENTROPY URL
            # ------------------------------------------------

            entropy = calculate_entropy(parsed.path)

            if entropy > 4.5 and len(parsed.path) > 20:

                reasons.append(
                    "URL path contains unusually high character entropy."
                )

                indicators.append("HIGH_ENTROPY")
                score += 4


            # ------------------------------------------------
            # MANY QUERY PARAMETERS
            # ------------------------------------------------

            if parsed.query:

                parameter_count = parsed.query.count("&") + 1

                if parameter_count >= 5:

                    reasons.append(
                        "URL contains an unusually large number of parameters."
                    )

                    indicators.append("MANY_PARAMETERS")
                    score += 4


            if reasons:

                results.append({
                    "url": url,
                    "score": score,
                    "indicators": indicators,
                    "reasons": reasons
                })

                total_score += score

        except Exception:

            results.append({
                "url": url,
                "score": 5,
                "indicators": ["INVALID_URL"],
                "reasons": [
                    "URL could not be safely parsed."
                ]
            })

            total_score += 5

    return results, total_score


# ============================================================
# 4. KEYWORD ANALYSIS
# ============================================================

def analyze_keywords(message):

    text = message.lower()

    results = []
    score = 0

    detected_phrases = set()
    detected_keywords = set()

    # Phrases
    for phrase, points in SUSPICIOUS_PHRASES.items():

        if phrase in text:

            detected_phrases.add(phrase)

            results.append({
                "type": "Suspicious Phrase",
                "value": phrase,
                "points": points
            })

            score += points


    # Keywords
    for keyword, points in SUSPICIOUS_KEYWORDS.items():

        pattern = r"\b" + re.escape(keyword) + r"\b"

        if re.search(pattern, text):

            # Avoid unnecessary duplicate keyword detections
            if keyword not in detected_keywords:

                detected_keywords.add(keyword)

                results.append({
                    "type": "Suspicious Keyword",
                    "value": keyword,
                    "points": points
                })

                score += points

    return results, score


# ============================================================
# 5. SOCIAL ENGINEERING ANALYSIS
# ============================================================

def analyze_social_engineering(message):

    text = message.lower()

    flags = []
    categories = []
    score = 0


    # URGENCY
    urgency = [
        "urgent",
        "immediately",
        "act now",
        "don't delay",
        "within 24 hours",
        "within 48 hours",
        "limited time"
    ]

    if any(item in text for item in urgency):

        flags.append(
            "Urgency or pressure tactics detected."
        )

        categories.append("URGENCY")
        score += 7


    # FEAR
    fear = [
        "suspended",
        "blocked",
        "locked",
        "legal action",
        "penalty",
        "fine",
        "terminated"
    ]

    if any(item in text for item in fear):

        flags.append(
            "Fear or threat-based language detected."
        )

        categories.append("FEAR")
        score += 7


    # CREDENTIAL THEFT
    credentials = [
        "password",
        "username",
        "login",
        "otp",
        "credential"
    ]

    if any(item in text for item in credentials):

        flags.append(
            "Possible credential or authentication information request."
        )

        categories.append("CREDENTIAL_THEFT")
        score += 10


    # FINANCIAL FRAUD
    financial = [
        "credit card",
        "debit card",
        "bank account",
        "card details",
        "payment information",
        "bank details"
    ]

    if any(item in text for item in financial):

        flags.append(
            "Possible financial information request."
        )

        categories.append("FINANCIAL_FRAUD")
        score += 10


    # PRIZE BAIT
    prizes = [
        "winner",
        "prize",
        "lottery",
        "reward",
        "free gift"
    ]

    if any(item in text for item in prizes):

        flags.append(
            "Prize or reward-based bait detected."
        )

        categories.append("PRIZE_BAIT")
        score += 6


    # CALL TO ACTION
    actions = [
        "click here",
        "click the link",
        "open the link",
        "download now",
        "verify now",
        "login now"
    ]

    if any(item in text for item in actions):

        flags.append(
            "Strong call-to-action detected."
        )

        categories.append("CALL_TO_ACTION")
        score += 6


    # IMPERSONATION
    authority = [
        "bank",
        "government",
        "police",
        "tax department",
        "microsoft",
        "google",
        "amazon",
        "paypal",
        "apple"
    ]

    if any(item in text for item in authority):

        flags.append(
            "Possible organization or authority impersonation."
        )

        categories.append("IMPERSONATION")
        score += 5


    # EXCESSIVE EXCLAMATION
    if message.count("!") >= 3:

        flags.append(
            "Excessive exclamation marks detected."
        )

        categories.append("EMOTIONAL_PRESSURE")
        score += 2


    return flags, categories, score


# ============================================================
# 6. SENDER ANALYSIS
# ============================================================

def analyze_sender(message):

    flags = []
    score = 0
    sender_email = None
    sender_domain = None

    # --------------------------------------------------------
    # a. FIRST: Try to identify the actual sender
    #    from "From:" or "From"
    # --------------------------------------------------------

    sender_match = re.search(
        r'(?:From\s*[:\-]?\s*[^<\n]*?)([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        message,
        re.IGNORECASE
    )

    if sender_match:
        sender_email = sender_match.group(1).lower()

    else:
        # ----------------------------------------------------
        # b. FALLBACK: Find an email address in the message
        # ----------------------------------------------------
        emails = re.findall(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            message
        )

        if not emails:
            return [], 0, None, None

        sender_email = emails[0].lower()

    # --------------------------------------------------------
    # c. Extract domain
    # --------------------------------------------------------

    sender_domain = sender_email.split("@")[-1]

    # --------------------------------------------------------
    # FREE EMAIL PROVIDER
    # --------------------------------------------------------

    free_domains = {
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "proton.me",
        "protonmail.com"
    }

    if sender_domain in free_domains:
        flags.append(
            f"Sender uses a free email provider: {sender_domain}"
        )
        score += 2

    # --------------------------------------------------------
    # SECURITY / SERVICE WORDS
    # --------------------------------------------------------

    suspicious_sender_words = {
        "admin",
        "support",
        "security",
        "verify",
        "account",
        "service",
        "alert",
        "help",
        "billing"
    }

    local_part = sender_email.split("@")[0].lower()

    found_words = [
        word
        for word in suspicious_sender_words
        if word in local_part
    ]

    if found_words:
        flags.append(
            "Sender address contains security/service-related terms: "
            + ", ".join(found_words)
        )

        score += min(len(found_words) * 2, 6)

    # --------------------------------------------------------
    # MANY NUMBERS
    # --------------------------------------------------------

    if re.search(r"\d{4,}", local_part):
        flags.append(
            "Sender address contains an unusually long numeric sequence."
        )
        score += 3

    # --------------------------------------------------------
    # MANY SPECIAL CHARACTERS
    # --------------------------------------------------------

    special_count = len(
        re.findall(r"[^a-zA-Z0-9]", local_part)
    )

    if special_count >= 4:
        flags.append(
            "Sender username contains an unusually high number "
            "of special characters."
        )
        score += 3

    return flags, score, sender_email, sender_domain

# ============================================================
# 7. BRAND IMPERSONATION DETECTION
# ============================================================

def levenshtein_distance(a, b):

    if len(a) < len(b):
        return levenshtein_distance(b, a)

    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))

    for i, char_a in enumerate(a, start=1):

        current_row = [i]

        for j, char_b in enumerate(b, start=1):

            insertions = current_row[j - 1] + 1
            deletions = previous_row[j] + 1
            substitutions = previous_row[j - 1]

            if char_a != char_b:
                substitutions += 1

            current_row.append(
                min(
                    insertions,
                    deletions,
                    substitutions
                )
            )

        previous_row = current_row

    return previous_row[-1]


KNOWN_BRANDS = {
    "google",
    "microsoft",
    "amazon",
    "apple",
    "paypal",
    "facebook",
    "instagram",
    "netflix"
}


def analyze_brand_impersonation(message):

    text = message.lower()

    flags = []
    score = 0

    words = re.findall(r"[a-z0-9]+", text)

    detected = set()

    for word in words:

        if len(word) < 5:
            continue

        for brand in KNOWN_BRANDS:

            distance = levenshtein_distance(
                word,
                brand
            )

            if (
                distance <= 1
                and word != brand
                and brand not in detected
            ):

                flags.append(
                    f"Possible misspelled brand name: '{word}' resembles '{brand}'."
                )

                detected.add(brand)
                score += 12

    return flags, score


# ============================================================
# 8. MESSAGE OBFUSCATION DETECTION
# ============================================================

def analyze_obfuscation(message):

    flags = []
    score = 0

    # Excessive unusual characters
    unusual_chars = re.findall(
        r"[^a-zA-Z0-9\s.,!?@:/_-]",
        message
    )

    if len(unusual_chars) >= 8:

        flags.append(
            "Message contains an unusually high number of special characters."
        )

        score += 3


    # Character substitution patterns
    substitution_pattern = re.compile(
        r"[a-zA-Z][0-9][a-zA-Z]"
    )

    if substitution_pattern.search(message):

        flags.append(
            "Possible character substitution or text obfuscation detected."
        )

        score += 4


    # Excessive whitespace
    if re.search(r"\s{5,}", message):

        flags.append(
            "Unusual spacing patterns detected."
        )

        score += 2


    return flags, score


# ============================================================
# 9. RISK ENGINE
# ============================================================

def calculate_risk(
    keyword_score,
    url_score,
    social_score,
    sender_score,
    brand_score,
    obfuscation_score
):

    raw_score = (
        keyword_score
        + url_score
        + social_score
        + sender_score
        + brand_score
        + obfuscation_score
    )

    return min(raw_score, 100)


def get_risk_level(score):

    if score >= 75:
        return "CRITICAL"

    elif score >= 50:
        return "HIGH"

    elif score >= 25:
        return "MEDIUM"

    return "LOW"


def get_confidence(score):

    if score >= 75:
        return "Very High"

    elif score >= 50:
        return "High"

    elif score >= 25:
        return "Moderate"

    return "Low"


# ============================================================
# 10. ATTACK TYPE CLASSIFICATION
# ============================================================

def classify_attack(categories, message):

    text = message.lower()

    if "CREDENTIAL_THEFT" in categories:
        return "Credential Phishing"

    if "FINANCIAL_FRAUD" in categories:
        return "Financial Phishing"

    if "PRIZE_BAIT" in categories:
        return "Prize / Reward Scam"

    if "IMPERSONATION" in categories:
        return "Impersonation Phishing"

    if "URGENCY" in categories and "FEAR" in categories:
        return "Social Engineering Attack"

    if "CALL_TO_ACTION" in categories:
        return "Malicious Link / Action Request"

    if "otp" in text:
        return "OTP / Authentication Scam"

    return "General Suspicious Message"


# ============================================================
# 11. EXPLANATION ENGINE
# ============================================================

def generate_explanation(
    risk_level,
    keyword_results,
    url_results,
    social_flags,
    sender_flags,
    brand_flags,
    obfuscation_flags
):

    reasons = []

    if keyword_results:
        reasons.append(
            f"{len(keyword_results)} suspicious keyword/phrase indicators detected."
        )

    if url_results:
        reasons.append(
            f"{len(url_results)} suspicious URL(s) detected."
        )

    if social_flags:
        reasons.append(
            f"{len(social_flags)} social-engineering indicators detected."
        )

    if sender_flags:
        reasons.append(
            f"{len(sender_flags)} sender-related indicators detected."
        )

    if brand_flags:
        reasons.append(
            "Possible brand impersonation detected."
        )

    if obfuscation_flags:
        reasons.append(
            "Possible message obfuscation detected."
        )


    if risk_level == "CRITICAL":

        conclusion = (
            "The message contains multiple strong phishing indicators. "
            "Treat it as highly suspicious and avoid interacting with it."
        )

    elif risk_level == "HIGH":

        conclusion = (
            "The message contains several characteristics commonly "
            "associated with phishing or social engineering."
        )

    elif risk_level == "MEDIUM":

        conclusion = (
            "The message contains suspicious characteristics that "
            "require additional verification."
        )

    else:

        conclusion = (
            "Few phishing indicators were detected. This does not "
            "guarantee that the message is safe."
        )


    return reasons, conclusion


# ============================================================
# 12. JSON REPORT
# ============================================================

def create_report(
    message,
    score,
    risk_level,
    confidence,
    attack_type,
    keyword_results,
    url_results,
    social_flags,
    social_categories,
    sender_flags,
    sender_email,
    sender_domain,
    brand_flags,
    obfuscation_flags
):

    report = {

        "project": "Phishing Message Identifier",

        "version": VERSION,

        "timestamp": datetime.now().isoformat(),

        "analysis": {

            "risk_score": score,

            "risk_level": risk_level,

            "confidence": confidence,

            "attack_type": attack_type
        },

        "sender": {

            "email": sender_email,

            "domain": sender_domain,

            "indicators": sender_flags
        },

        "keywords": keyword_results,

        "urls": url_results,

        "social_engineering": {

            "categories": social_categories,

            "indicators": social_flags
        },

        "brand_impersonation": brand_flags,

        "obfuscation": obfuscation_flags,

        "message_length": len(message)

    }

    return report


def save_report(report):

    filename = (
        "phishing_report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".json"
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return filename


# ============================================================
# 13. TERMINAL DISPLAY
# ============================================================

def display_results(
    score,
    risk_level,
    confidence,
    attack_type,
    keyword_results,
    url_results,
    social_flags,
    sender_flags,
    sender_email,
    sender_domain,
    brand_flags,
    obfuscation_flags,
    explanation,
    conclusion
):

    print("\n")
    print("=" * 65)
    print("              ADVANCED PHISHING ANALYZER")
    print("=" * 65)

    print(f"Engine Version : {VERSION}")
    print(f"Risk Score     : {score}/100")
    print(f"Risk Level     : {risk_level}")
    print(f"Confidence     : {confidence}")
    print(f"Attack Type    : {attack_type}")


    print("\n" + "-" * 65)
    print("SUSPICIOUS KEYWORDS / PHRASES")
    print("-" * 65)

    if keyword_results:

        for item in keyword_results:

            print(
                f"• {item['value']} "
                f"(+{item['points']})"
            )

    else:

        print("No suspicious keywords detected.")


    print("\n" + "-" * 65)
    print("URL INTELLIGENCE")
    print("-" * 65)

    if url_results:

        for item in url_results:

            print(f"\nURL: {item['url']}")
            print(f"Risk Points: {item['score']}")

            for indicator in item["indicators"]:
                print(f"  Indicator: {indicator}")

            for reason in item["reasons"]:
                print(f"  • {reason}")

    else:

        print("No suspicious URLs detected.")


    print("\n" + "-" * 65)
    print("SOCIAL ENGINEERING")
    print("-" * 65)

    if social_flags:

        for flag in social_flags:
            print(f"• {flag}")

    else:

        print("No major social-engineering indicators detected.")


    print("\n" + "-" * 65)
    print("SENDER ANALYSIS")
    print("-" * 65)

    if sender_email:

        print(f"Email  : {sender_email}")
        print(f"Domain : {sender_domain}")

        for flag in sender_flags:
            print(f"• {flag}")

    else:

        print("No email address detected.")


    print("\n" + "-" * 65)
    print("BRAND IMPERSONATION")
    print("-" * 65)

    if brand_flags:

        for flag in brand_flags:
            print(f"• {flag}")

    else:

        print("No obvious brand impersonation detected.")


    print("\n" + "-" * 65)
    print("OBFUSCATION ANALYSIS")
    print("-" * 65)

    if obfuscation_flags:

        for flag in obfuscation_flags:
            print(f"• {flag}")

    else:

        print("No major obfuscation indicators detected.")


    print("\n" + "-" * 65)
    print("WHY THIS MESSAGE MAY BE UNSAFE")
    print("-" * 65)

    if explanation:

        for reason in explanation:
            print(f"• {reason}")

    else:

        print("No major reasons identified.")


    print("\n" + "-" * 65)
    print("CONCLUSION")
    print("-" * 65)

    print(conclusion)


    print("\n" + "-" * 65)
    print("SAFETY RECOMMENDATION")
    print("-" * 65)

    if risk_level in ["CRITICAL", "HIGH"]:

        print(
            "Avoid clicking links, opening unexpected attachments, "
            "or providing passwords, OTPs, or financial information."
        )

    elif risk_level == "MEDIUM":

        print(
            "Verify the sender and destination independently "
            "before interacting with the message."
        )

    else:

        print(
            "No major indicators were detected, but remain cautious."
        )

    print("\n" + "=" * 65)


# ============================================================
# 14. MAIN ANALYSIS PIPELINE
# ============================================================

def analyze_message(message):

    # URL extraction
    urls = extract_urls(message)

    # Keyword engine
    keyword_results, keyword_score = analyze_keywords(message)

    # URL engine
    url_results, url_score = analyze_urls(urls)

    # Social engineering
    social_flags, social_categories, social_score = (
        analyze_social_engineering(message)
    )

    # Sender analysis
    sender_flags, sender_score, sender_email, sender_domain = (
        analyze_sender(message)
    )

    # Brand impersonation
    brand_flags, brand_score = (
        analyze_brand_impersonation(message)
    )

    # Obfuscation
    obfuscation_flags, obfuscation_score = (
        analyze_obfuscation(message)
    )

    # Final risk
    final_score = calculate_risk(
        keyword_score,
        url_score,
        social_score,
        sender_score,
        brand_score,
        obfuscation_score
    )

    # Risk level
    risk_level = get_risk_level(final_score)

    # Confidence
    confidence = get_confidence(final_score)

    # Attack classification
    attack_type = classify_attack(
        social_categories,
        message
    )

    # Explanation
    explanation, conclusion = generate_explanation(
        risk_level,
        keyword_results,
        url_results,
        social_flags,
        sender_flags,
        brand_flags,
        obfuscation_flags
    )

    return {
        "score": final_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "attack_type": attack_type,

        "keyword_results": keyword_results,

        "url_results": url_results,

        "social_flags": social_flags,

        "social_categories": social_categories,

        "sender_flags": sender_flags,

        "sender_email": sender_email,

        "sender_domain": sender_domain,

        "brand_flags": brand_flags,

        "obfuscation_flags": obfuscation_flags,

        "explanation": explanation,

        "conclusion": conclusion
    }


# ============================================================
# 15. MAIN PROGRAM
# ============================================================

def main():

    print("\n")
    print("=" * 45)
    print("             SCAM MESSAGE IDENTIFIER")
    print("                    v2.0")
    print("=" * 45)

    print("\nPaste the email/message below.")
    print("Type END/end on a separate line when the message is finished.\n")

    lines = []

    while True:

        try:
            line = input()

        except EOFError:
            break

        if line.strip().upper() == "END":
            break

        lines.append(line)


    message = "\n".join(lines)


    if not message.strip():

        print("\nNo message entered.")
        return


    print("\nAnalyzing message...")


    result = analyze_message(message)


    display_results(
        result["score"],
        result["risk_level"],
        result["confidence"],
        result["attack_type"],
        result["keyword_results"],
        result["url_results"],
        result["social_flags"],
        result["sender_flags"],
        result["sender_email"],
        result["sender_domain"],
        result["brand_flags"],
        result["obfuscation_flags"],
        result["explanation"],
        result["conclusion"]
    )


    # --------------------------------------------------------
    # ASK WHETHER TO SAVE JSON REPORT
    # --------------------------------------------------------

    save_choice = input(
        "\nSave detailed JSON report? (y/n): "
    ).strip().lower()


    if save_choice == "y":

        report = create_report(
            message,
            result["score"],
            result["risk_level"],
            result["confidence"],
            result["attack_type"],
            result["keyword_results"],
            result["url_results"],
            result["social_flags"],
            result["social_categories"],
            result["sender_flags"],
            result["sender_email"],
            result["sender_domain"],
            result["brand_flags"],
            result["obfuscation_flags"]
        )

        filename = save_report(report)

        print(
            f"\nDetailed report saved as: {filename}"
        )


    print("\nAnalysis completed.")


if __name__ == "__main__":
    main()