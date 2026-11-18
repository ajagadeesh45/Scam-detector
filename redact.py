"""Remove personal contact details (phone numbers, e-mails) from text.

Used on the training data and on every message before it reaches the ML model,
so the model never learns or stores real phone numbers.
"""
import re

PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"   # Indian mobile numbers
    r"|(?<!\d)0\d{9,10}(?!\d)"                                  # 0-prefixed long numbers (UK / STD style)
    r"|(?<!\d)\+?\d{1,3}[\s-]\d{3,5}[\s-]\d{4,6}(?!\d)"         # spaced international numbers
    r"|(?<!\d)\d{9,}"                                          # any other long digit run (phones, card/account numbers)
)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def redact(text: str) -> str:
    text = EMAIL_RE.sub("EMAILADDR", text)
    return PHONE_RE.sub("PHONENUM", text)
