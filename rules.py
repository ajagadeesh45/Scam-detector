"""Rule-based red-flag checks tuned for Indian SMS / WhatsApp scams.

Each rule: (name, plain-language explanation, regex, weight).
"""
import re

ASK = r"(share|send|give|tell|provide|enter|submit|confirm|verify|forward|reply with|type)"

RULES = [
    ("Asks for OTP / PIN / password",
     "Banks and government bodies never ask for your OTP, UPI PIN or password.",
     rf"({ASK}.{{0,25}}\b(otp|upi pin|mpin|atm pin|cvv|password|pin)\b|\b(otp|upi pin|mpin|cvv)\b.{{0,25}}{ASK}\b(?! it with anyone))", 30),
    ("Fake KYC / account-block threat",
     "Scammers threaten to block your account or SIM so you act without thinking.",
     r"(kyc|account.{0,25}(blocked|suspended|closed|freez|deactivat)|sim.{0,15}(block|deactivat)|pan.{0,15}(update|expire|block)|card.{0,25}(deactivat|blocked))", 30),
    ("Urgency / pressure",
     "Real organisations give you time. Scammers rush you.",
     r"(urgent|immediately|within \d+ ?(hours|hrs|minutes|mins)|last chance|act now|expires? (today|soon|tonight)|final notice|before midnight|tonight)", 15),
    ("Lottery / prize / reward bait",
     "You cannot win a lottery or prize you never entered.",
     r"(lottery|you (have )?won|winner|prize|lucky draw|congratulations|cashback|reward points|kbc)", 25),
    ("Free gift / free recharge bait",
     "'Free' recharge, data or gifts are a common way to get you to click a bad link.",
     r"(free (recharge|gift|data|iphone|gold|laptop)|claim (your )?(free )?(gift|reward|offer))", 25),
    ("Job / work-from-home / task bait",
     "Easy daily income for liking videos or doing small tasks is a known scam.",
     r"(work from home|part.?time job|earn (rs\.?|₹)? ?\d+|per day income|daily income|data entry job|task.{0,10}(earn|commission)|like (youtube )?videos)", 25),
    ("Investment / crypto guaranteed returns",
     "No genuine investment guarantees high profit in a few days.",
     r"(guaranteed (profit|returns?)|\d{2,3}% (profit|returns?)|double your money|crypto trading group|trading group|stock tips? group)", 30),
    ("Asks you to install an app / APK",
     "Remote-access apps and APK files let scammers take over your phone.",
     r"(\.apk\b|install .{0,20}app|download .{0,25}app|anydesk|teamviewer|quicksupport|rustdesk)", 30),
    ("Impersonates electricity / courier / customs",
     "Utility and courier scams ask for a quick 'fee' or threaten disconnection.",
     r"(electricity.{0,30}(disconnect|bill)|power.{0,15}(cut|disconnect)|parcel.{0,25}(held|stuck|customs)|customs (duty|charges?|fee)|courier.{0,25}(fee|failed|stuck)|fedex|dhl|india post)", 20),
    ("Asks for money / fee / transfer",
     "Genuine prizes, refunds and jobs never need an upfront fee.",
     r"(processing fee|registration fee|send (rs|₹)|pay (rs|₹)|transfer (rs|₹)|pay .{0,15}(fee|charges)|refund.{0,25}(click|link|upi pin))", 20),
    ("Instant loan / credit bait",
     "Loan apps that approve instantly often steal data or harass later.",
     r"(instant loan|pre.?approved loan|loan approved|credit limit increase)", 15),
    ("Arrest / police / legal threat",
     "'Digital arrest' does not exist. No agency arrests people over video call.",
     r"(arrest|cbi|police case|narcotics|ncb\b|legal action|customs officer|digital arrest|non.?bailable|video call.{0,40}(do not|don't) (tell|disconnect))", 30),
    ("Romance / overseas gift / inheritance story",
     "Strangers abroad who want to send you gifts or money will ask for fees next.",
     r"(gift box|army officer deployed|inheritance|i like your profile|special connection|help me transfer)", 25),
    ("Tamil / Hindi / Tanglish scam words",
     "Scam wording in local languages: account block, lottery, OTP requests.",
     r"(block (aagum|ho jayega)|kyc update pann|otp (anuppu|batao|share karo|sollu)|khata band|aapka account|inam (vizh|kidai)|lottery (vandh|lagi)|கணக்கு.{0,10}(முடக்க|தடை)|பரிசு|லாட்டரி|ஓடிபி|खाता.{0,10}(बंद|ब्लॉक)|ओटीपी|इनाम|लॉटरी|केवाईसी)", 25),
]

SHORTENERS = r"(bit\.ly|tinyurl|t\.co|goo\.gl|cutt\.ly|rb\.gy|is\.gd|shorturl|wa\.me|t\.me)"
BAD_TLDS = r"\.(top|xyz|click|live|site|online|icu|vip|cc|buzz|work|shop|link|rest|monster|cfd|sbs)(\b|/)"
BRANDS = r"(sbi|hdfc|icici|axis|kotak|pnb|canara|paytm|phonepe|gpay|amazon|flipkart|airtel|jio|irctc|uidai|aadhaar|incometax)"

URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+|\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(top|xyz|click|live|site|online|icu|vip|cc|buzz|net|com|in)(/[^\s]*)?)", re.I)


def extract_urls(text: str):
    return [m.group(0).rstrip(".,)") for m in URL_RE.finditer(text)]


def check(text: str):
    """Return (flags, score). Each flag is a dict: name, why, match."""
    t = text.lower()
    flags, score = [], 0

    for name, why, pattern, w in RULES:
        m = re.search(pattern, t, re.I)
        if m:
            flags.append({"name": name, "why": why, "match": text[m.start():m.end()]})
            score += w

    urls = extract_urls(text)
    if re.search(SHORTENERS, t):
        flags.append({"name": "Shortened / messaging link", "why": "Short links hide where they really go.",
                      "match": next((u for u in urls if re.search(SHORTENERS, u.lower())), "")})
        score += 20
    elif urls:
        bad = [u for u in urls if re.search(BAD_TLDS, u.lower())]
        brand_fake = [u for u in urls if re.search(BRANDS, u.lower()) and re.search(r"-|\.(top|xyz|click|live|site|online|icu|vip|cc|buzz|net)\b", u.lower())]
        if bad or brand_fake:
            flags.append({"name": "Suspicious website address", "why": "Odd endings (.top, .xyz) or bank names inside strange domains are fake-site signs.",
                          "match": (bad or brand_fake)[0]})
            score += 25
        else:
            flags.append({"name": "Contains a link", "why": "Open links from messages only if you fully trust the sender.", "match": urls[0]})
            score += 10

    if re.search(r"\b\d{10}\b|\+91[\s-]?\d{10}|phonenum", t):
        flags.append({"name": "Asks you to call / message a number", "why": "Scammers want you on a call where they can pressure you.",
                      "match": (re.search(r"(\+91[\s-]?)?\d{10}|phonenum", t) or [None])[0] or ""})
        score += 5
    if len(re.findall(r"[A-Z]{4,}", text)) >= 3:
        flags.append({"name": "Excessive CAPITAL LETTERS", "why": "Shouting text is used to create panic.", "match": ""})
        score += 5

    return flags, min(score, 100)
