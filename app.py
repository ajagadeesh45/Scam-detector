import html
import streamlit as st
from detector import analyze
from rules import extract_urls

st.set_page_config(page_title="ScamShield India", page_icon="🛡️", layout="centered")

# ---------- styling ----------
st.markdown("""
<style>
#MainMenu, footer, header {visibility: hidden;}
.block-container {padding-top: 2rem; max-width: 760px;}
.hero {text-align:center; padding: 1.2rem 0 0.6rem;}
.hero h1 {font-size: 2.3rem; margin-bottom: 0.2rem; letter-spacing: -0.5px;}
.hero p {color:#6B7280; font-size:1.05rem; margin:0;}
.badge {display:inline-block; background:#EEF2FF; color:#4F46E5; padding:3px 12px; border-radius:999px;
        font-size:0.78rem; font-weight:600; margin-bottom:0.6rem;}
.result {border-radius:16px; padding:1.3rem 1.5rem; margin:1rem 0; border:1px solid;}
.result.high {background:#FEF2F2; border-color:#FCA5A5;}
.result.medium {background:#FFFBEB; border-color:#FCD34D;}
.result.low {background:#F0FDF4; border-color:#86EFAC;}
.result h2 {margin:0 0 0.2rem; font-size:1.5rem;}
.result .sub {color:#4B5563; margin:0;}
.meter {height:10px; border-radius:999px; background:#E5E7EB; margin-top:0.9rem; overflow:hidden;}
.meter > div {height:100%; border-radius:999px;}
.flag {background:#fff; border:1px solid #E5E7EB; border-left:4px solid #EF4444; border-radius:10px;
       padding:0.7rem 0.9rem; margin-bottom:0.6rem;}
.flag b {color:#111827;} .flag span {color:#6B7280; font-size:0.92rem; display:block; margin-top:2px;}
.flag code {background:#FEE2E2; color:#991B1B; padding:1px 6px; border-radius:6px; font-size:0.85rem;}
.msgbox {background:#F9FAFB; border:1px solid #E5E7EB; border-radius:12px; padding:0.9rem 1rem; line-height:1.6;}
mark {background:#FECACA; color:#7F1D1D; padding:0 3px; border-radius:4px;}
.advice {background:#EEF2FF; border-radius:12px; padding:1rem 1.2rem; color:#1E1B4B;}
.small {color:#6B7280; font-size:0.85rem;}
.stButton>button {border-radius:10px; font-weight:600;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <span class="badge">FREE · NO LOGIN · MESSAGES ARE NOT STORED</span>
  <h1>🛡️ ScamShield India</h1>
  <p>Paste any suspicious SMS or WhatsApp message. Find out if it's a scam in seconds.</p>
</div>
""", unsafe_allow_html=True)

SAMPLES = {
    "🏦 Fake KYC": "Dear customer, your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz",
    "🎁 Lottery": "CONGRATULATIONS! You have won Rs 25,00,000 in KBC lucky draw. Send registration fee Rs 5000 to claim your prize.",
    "💼 Job offer": "Part time job, earn 4000 daily from home, just like youtube videos. Join telegram t.me/earnfast",
    "👮 Digital arrest": "This is CBI. A parcel in your name has drugs. You are under digital arrest. Stay on video call and do not tell anyone.",
    "✅ Normal": "Your SBI a/c XX9921 credited with Rs 15,000 on 18-Nov. Avl bal Rs 31,240.",
}

ADVICE = {
    "English": ("Don't click links or call the number. Never share OTP, UPI PIN or card details with anyone. "
                "Report at <b>cybercrime.gov.in</b> or call <b>1930</b>. Forward spam SMS to <b>1909</b>."),
    "தமிழ்": ("இணைப்புகளை கிளிக் செய்ய வேண்டாம், அந்த எண்ணை அழைக்க வேண்டாம். OTP, UPI PIN அல்லது கார்டு விவரங்களை யாருடனும் பகிர வேண்டாம். "
              "<b>cybercrime.gov.in</b>-இல் புகார் அளிக்கவும் அல்லது <b>1930</b> எண்ணை அழைக்கவும்."),
    "हिन्दी": ("लिंक पर क्लिक न करें और उस नंबर पर कॉल न करें। OTP, UPI PIN या कार्ड की जानकारी किसी को न बताएं। "
              "<b>cybercrime.gov.in</b> पर शिकायत करें या <b>1930</b> पर कॉल करें।"),
}
SAFE_ADVICE = {
    "English": "Looks fine, but stay careful. No genuine bank or government body asks for your OTP or PIN.",
    "தமிழ்": "பாதுகாப்பாகத் தெரிகிறது, ஆனால் கவனமாக இருங்கள். எந்த வங்கியும் அரசு அமைப்பும் உங்கள் OTP அல்லது PIN கேட்காது.",
    "हिन्दी": "सुरक्षित लगता है, फिर भी सावधान रहें। कोई भी बैंक या सरकारी संस्था आपसे OTP या PIN नहीं मांगती।",
}

tab_check, tab_about = st.tabs(["🔍 Check a message", "ℹ️ How it works"])

with tab_check:
    if "msg" not in st.session_state:
        st.session_state.msg = ""

    st.caption("Try an example:")
    cols = st.columns(len(SAMPLES))
    for c, (label, text) in zip(cols, SAMPLES.items()):
        if c.button(label, use_container_width=True, key=label):
            st.session_state.msg = text

    msg = st.text_area("Message to check", key="msg", height=140,
                       placeholder="Paste the SMS / WhatsApp message here...", label_visibility="collapsed")
    lang = st.radio("Advice language", list(ADVICE.keys()), horizontal=True)
    go = st.button("🔎 Check message", type="primary", use_container_width=True)

    if go:
        if not msg.strip():
            st.warning("Please paste a message first.")
        else:
            with st.spinner("Analysing..."):
                r = analyze(msg)
            level, score = r["level"], r["score"]
            cfg = {"High": ("high", "🔴 Likely a SCAM", "Do not respond to this message.", "#DC2626"),
                   "Medium": ("medium", "🟠 Suspicious", "Be careful. Verify through the official app or website.", "#F59E0B"),
                   "Low": ("low", "🟢 Looks safe", "No strong scam signs found.", "#16A34A")}[level]
            st.markdown(f"""
            <div class="result {cfg[0]}">
              <h2>{cfg[1]}</h2>
              <p class="sub">{cfg[2]} &nbsp;·&nbsp; Risk score <b>{score}/100</b></p>
              <div class="meter"><div style="width:{max(score,3)}%; background:{cfg[3]};"></div></div>
            </div>""", unsafe_allow_html=True)

            # highlighted message
            safe_text = html.escape(msg)
            for f in r["flags"]:
                m = f["match"].strip()
                if m and len(m) > 2:
                    safe_text = safe_text.replace(html.escape(m), f"<mark>{html.escape(m)}</mark>", 1) if html.escape(m) in safe_text else safe_text
            st.markdown("**Your message** (suspicious parts highlighted)")
            st.markdown(f'<div class="msgbox">{safe_text}</div>', unsafe_allow_html=True)

            if r["flags"]:
                st.markdown(f"#### ⚠️ {len(r['flags'])} red flag{'s' if len(r['flags'])>1 else ''} found")
                for f in r["flags"]:
                    found = f' <code>{html.escape(f["match"].strip())}</code>' if f["match"].strip() else ""
                    st.markdown(f'<div class="flag"><b>{f["name"]}</b>{found}<span>{f["why"]}</span></div>', unsafe_allow_html=True)

            urls = extract_urls(msg)
            if urls:
                st.caption("Links found (do not open): " + ", ".join(f"`{u}`" for u in urls))

            st.markdown("#### 🛡️ What to do")
            st.markdown(f'<div class="advice">{ADVICE[lang] if level != "Low" else SAFE_ADVICE[lang]}</div>', unsafe_allow_html=True)

            with st.expander("See how the score was calculated"):
                c1, c2 = st.columns(2)
                c1.metric("Pattern rules", f"{r['rule_score']}/100")
                c2.metric("AI model (spam probability)", f"{r['ml_prob']}%")
                st.caption("Final score blends both. Strong rule matches can raise the alarm on their own.")

with tab_about:
    st.markdown("""
### How ScamShield works
1. **Pattern rules** look for known Indian scam tricks: fake KYC, OTP requests, lottery and job bait,
   digital arrest threats, courier and electricity fee scams, fake links and more.
2. **An AI model** (TF-IDF + Logistic Regression) trained on the public SMS Spam Collection and a 14,000-message
   Indian scam dataset gives a spam probability.
3. Both scores are blended into a risk level: **Low, Medium or High**.

### Golden rules
- No bank, police or government office asks for your **OTP, UPI PIN or password**.
- **"Digital arrest" is not real.** No agency arrests anyone over a video call.
- You can't win a lottery you never entered.
- Genuine jobs, prizes and refunds never need an **upfront fee**.

### Report cyber fraud
- Call **1930** (National Cyber Crime Helpline)
- File a complaint at **cybercrime.gov.in**
- Forward spam SMS to **1909**

### Limits
This is a helper, not a guarantee. It can miss new scam styles and sometimes flags genuine messages.
When in doubt, contact your bank using the number on your card or official app.
""")
    st.markdown('<p class="small">Built with Python, scikit-learn and Streamlit. Messages are processed in memory and never stored.</p>',
                unsafe_allow_html=True)
