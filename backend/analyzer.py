import re

# Regex patterns for various PII and interesting data
URL_PATTERN = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
PHONE_PATTERN = r'\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b'
CREDIT_CARD_PATTERN = r'\b(?:\d[ -]*?){13,16}\b'
SSN_PATTERN = r'\b\d{3}-\d{2}-\d{4}\b'

# Simple name detection pattern (capitalized names)
NAME_PATTERN = r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b'

def analyze_payload(payload):
    if not payload:
        return {}

    results = {
        "urls": list(set(re.findall(URL_PATTERN, payload))),
        "emails": list(set(re.findall(EMAIL_PATTERN, payload))),
        "phones": list(set(re.findall(PHONE_PATTERN, payload))),
        "credit_cards": list(set(re.findall(CREDIT_CARD_PATTERN, payload))),
        "ssns": list(set(re.findall(SSN_PATTERN, payload))),
        "names": list(set(re.findall(NAME_PATTERN, payload)))
    }
    
    # Flatten phone tuples if necessary
    results["phones"] = ["".join(p) for p in results["phones"]]

    # Remove empty lists from results
    return {k: v for k, v in results.items() if v}

if __name__ == "__main__":
    test_payload = "Hello John Doe, your email is john.doe@example.com. Visit https://google.com for more info. Call me at 123-456-7890. Card: 1234 5678 1234 5678"
    print(analyze_payload(test_payload))
