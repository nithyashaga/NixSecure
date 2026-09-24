from pathlib import Path
import joblib
import pandas as pd
import json

ROOT=Path(__file__).resolve().parents[2]
MODEL=joblib.load(ROOT/"models"/"risk_model.pkl")
METRICS=json.loads((ROOT/"models"/"metrics.json").read_text())
FEATURES=METRICS["features"]

def predict(payload: dict):
    X=pd.DataFrame([{k:payload[k] for k in FEATURES}])
    pred=MODEL.predict(X)[0]
    probs=MODEL.predict_proba(X)[0]
    classes=list(MODEL.classes_)
    max_prob=float(max(probs))
    # Probability is used as an AI confidence signal; the displayed 0-100 risk score
    # is derived from the predicted class with a smooth confidence adjustment.
    bases={"LOW":20,"MEDIUM":50,"HIGH":80}
    score=bases[pred] + (max_prob-.5)*35
    score=max(0,min(100,score))
    return pred, round(score,1), dict(zip(classes,[round(float(p),4) for p in probs]))
