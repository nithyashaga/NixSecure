from pathlib import Path
import json
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import joblib

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "cybersecurity_risk_dataset.csv"
MODELS = ROOT / "models"
MODELS.mkdir(exist_ok=True)

FEATURES = ["device_type","failed_login_attempts","open_ports","total_vulnerabilities","critical_vulnerabilities","patch_age_days","network_anomaly_score","malware_alerts","privilege_escalation_attempts","previous_security_incidents"]
TARGET = "risk_level"

def make_data(n=1800, seed=42):
    rng = np.random.default_rng(seed)
    types = rng.choice(["Laptop","Desktop","Server","Workstation"], n, p=[.42,.20,.18,.20])
    failed = rng.poisson(5,n)
    ports = rng.poisson(5,n)
    vulns = rng.poisson(4,n)
    critical = np.minimum(vulns, rng.poisson(1.1,n))
    patch = rng.integers(0,121,n)
    anomaly = np.clip(rng.normal(38,22,n),0,100)
    malware = rng.poisson(.5,n)
    priv = rng.poisson(.6,n)
    incidents = rng.poisson(1.1,n)
    raw = (failed*1.8 + ports*1.4 + vulns*3.2 + critical*8 + patch*.22 + anomaly*.55 + malware*12 + priv*7 + incidents*5)
    q1,q2 = np.quantile(raw,[.47,.76])
    risk = np.where(raw<=q1,"LOW",np.where(raw<=q2,"MEDIUM","HIGH"))
    df = pd.DataFrame({"device_type":types,"failed_login_attempts":failed,"open_ports":ports,"total_vulnerabilities":vulns,"critical_vulnerabilities":critical,"patch_age_days":patch,"network_anomaly_score":np.round(anomaly,1),"malware_alerts":malware,"privilege_escalation_attempts":priv,"previous_security_incidents":incidents,"risk_level":risk})
    df.to_csv(DATA,index=False)
    return df

def train():
    df = make_data()
    X=df[FEATURES]; y=df[TARGET]
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
    cat=["device_type"]; num=[c for c in FEATURES if c not in cat]
    pre=ColumnTransformer([("cat",OneHotEncoder(handle_unknown="ignore"),cat),("num","passthrough",num)])
    models={
      "Logistic Regression": LogisticRegression(max_iter=1500),
      "Decision Tree": DecisionTreeClassifier(max_depth=7,random_state=42),
      "Random Forest": RandomForestClassifier(n_estimators=260,max_depth=10,random_state=42,class_weight="balanced")
    }
    metrics={}
    best=None; best_f1=-1
    for name, model in models.items():
        pipe=Pipeline([("pre",pre),("model",model)])
        pipe.fit(X_train,y_train)
        pred=pipe.predict(X_test)
        proba=pipe.predict_proba(X_test)
        classes=list(pipe.classes_)
        metrics[name]={
          "accuracy":round(accuracy_score(y_test,pred),4),
          "precision":round(precision_score(y_test,pred,average="weighted",zero_division=0),4),
          "recall":round(recall_score(y_test,pred,average="weighted",zero_division=0),4),
          "f1":round(f1_score(y_test,pred,average="weighted",zero_division=0),4),
          "roc_auc":round(roc_auc_score(y_test,proba,labels=classes,multi_class="ovr",average="weighted"),4),
          "confusion_matrix":confusion_matrix(y_test,pred,labels=["LOW","MEDIUM","HIGH"]).tolist()
        }
        if metrics[name]["f1"]>best_f1:
            best_f1=metrics[name]["f1"]; best=pipe
    # NixSecure uses Random Forest as its primary model by design; the other models are benchmarks.
    rf = Pipeline([("pre",pre),("model",models["Random Forest"])])
    rf.fit(X_train,y_train)
    best = rf
    joblib.dump(best,MODELS/"risk_model.pkl")
    (MODELS/"metrics.json").write_text(json.dumps({"features":FEATURES,"target":TARGET,"selected_model":"Random Forest","metrics":metrics,"dataset_note":"Synthetic prototype dataset generated for NixSecure. Metrics are evaluation results on this synthetic dataset and are not production performance claims."},indent=2))
    return metrics

if __name__ == "__main__":
    print(json.dumps(train(),indent=2))
