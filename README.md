# 🛡️ ScamShield India

Paste a suspicious SMS or WhatsApp message and get a risk level (Low / Medium / High), the exact red flags found, and what to do next, in English, Tamil or Hindi.

**Live demo:** _add your Streamlit link here_

## How it works
- **Pattern rules** for common Indian scams: fake KYC, OTP requests, lottery and job bait, digital arrest threats, courier and electricity fee scams, suspicious links and domains.
- **ML model** (TF-IDF word + character n-grams, Logistic Regression) trained on the public SMS Spam Collection and a 14,000-message Indian scam dataset.
- Both are blended into one 0-100 risk score. Messages are processed in memory and never stored.

## Run locally
```bash
pip install -r requirements.txt
python train.py          # optional: retrains model.joblib and prints evaluation
streamlit run app.py
```

## Project structure
| File | Purpose |
|---|---|
| `app.py` | Streamlit interface |
| `detector.py` | Combines rules and model into a score |
| `rules.py` | Red-flag rules with plain-language explanations |
| `model_utils.py`, `train.py` | Model training and evaluation |
| `data/` | Training data and hand-written test sets |
| `tests/test_detector.py` | Basic tests |

## Evaluation (honest numbers)
| Test | Accuracy |
|---|---|
| Held-out split of training data | ~99.5% (inflated: the Indian dataset is templated) |
| Hand-written messages, unseen when rules were tuned (`data/holdout_tests.csv`, 18 messages) | ~94% |

The hand-written sets are small. Treat them as a sanity check, not a benchmark. The detector can miss new scam styles and sometimes warns on genuine messages (for example, delivery OTPs).

## Data sources
- [SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) (UCI)
- Shade63/scam-classification-multiclass on Hugging Face (Indian-context scam messages). Check its license on the dataset page before redistributing.

## Report cyber fraud in India
Call **1930** · [cybercrime.gov.in](https://cybercrime.gov.in) · Forward spam SMS to **1909**

## License
MIT for the code. Datasets keep their original licenses.
