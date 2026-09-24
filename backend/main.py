import json, secrets
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database.db import Base, engine, get_db
from models.entities import User, Device, Prediction
from schemas.api import RegisterRequest, LoginRequest, DeviceOut, PredictionRequest, PredictionOut
from services.security import hash_password, verify_password
from services.risk import recommendations, FEATURE_LABELS
from ml.predictor import predict, METRICS
from seed import seed

Base.metadata.create_all(bind=engine)

# Initialize demo data if the production database is empty
seed()

TOKENS={}
app=FastAPI(title="NixSecure API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://nix-secure-roan.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ROOT=Path(__file__).resolve().parents[1]

def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401,"Authentication required")
    token=authorization.split(" ",1)[1]
    if token=="guest": return {"name":"Guest","email":"guest@nixsecure.local","guest":True}
    uid=TOKENS.get(token)
    if not uid: raise HTTPException(401,"Session expired")
    user=db.get(User,uid)
    if not user: raise HTTPException(401,"User not found")
    return {"id":user.id,"name":user.name,"email":user.email,"guest":False}

@app.get("/api/health")
def health(): return {"status":"ok","service":"NixSecure API"}

@app.post("/api/auth/register")
def register(req:RegisterRequest, db:Session=Depends(get_db)):
    email=req.email.lower()
    if db.query(User).filter_by(email=email).first(): raise HTTPException(409,"An account with this email already exists")
    user=User(name=req.name,email=email,password_hash=hash_password(req.password)); db.add(user); db.commit(); db.refresh(user)
    token=secrets.token_urlsafe(32); TOKENS[token]=user.id
    return {"token":token,"user":{"name":user.name,"email":user.email}}

@app.post("/api/auth/login")
def login(req:LoginRequest, db:Session=Depends(get_db)):
    user=db.query(User).filter_by(email=req.email.lower()).first()
    if not user or not verify_password(req.password,user.password_hash): raise HTTPException(401,"Invalid email or password")
    token=secrets.token_urlsafe(32); TOKENS[token]=user.id
    return {"token":token,"user":{"name":user.name,"email":user.email}}

@app.post("/api/auth/guest")
def guest(): return {"token":"guest","user":{"name":"Guest","email":"guest@nixsecure.local"}}

@app.get("/api/me")
def me(user=Depends(current_user)): return user

@app.get("/api/dashboard")
def dashboard(db:Session=Depends(get_db), user=Depends(current_user)):
    devices=db.query(Device).all(); latest={}
    for d in devices:
        p=db.query(Prediction).filter_by(device_id=d.id).order_by(Prediction.prediction_time.desc()).first()
        latest[d.id]=p
    scores=[p.risk_score for p in latest.values() if p]
    counts={"LOW":0,"MEDIUM":0,"HIGH":0}
    for p in latest.values():
        if p: counts[p.risk_level]+=1
    return {"total_devices":len(devices),"counts":counts,"overall_score":round(sum(scores)/len(scores),1) if scores else 0,"recent":[{"device":d.device_name,"score":latest[d.id].risk_score if latest[d.id] else None,"risk":latest[d.id].risk_level if latest[d.id] else "NOT ASSESSED","time":latest[d.id].prediction_time.isoformat() if latest[d.id] else None} for d in devices[:8]]}

@app.get("/api/devices",response_model=list[DeviceOut])
def devices(db:Session=Depends(get_db), user=Depends(current_user)): return db.query(Device).order_by(Device.device_name).all()

@app.get("/api/devices/{device_id}",response_model=DeviceOut)
def device(device_id:int,db:Session=Depends(get_db),user=Depends(current_user)):
    d=db.get(Device,device_id)
    if not d: raise HTTPException(404,"Device not found")
    return d

@app.get("/api/devices/{device_id}/predictions")
def device_predictions(device_id:int,db:Session=Depends(get_db),user=Depends(current_user)):
    rows=db.query(Prediction).filter_by(device_id=device_id).order_by(Prediction.prediction_time.desc()).all()
    return [{"id":p.id,"device_name":p.device.device_name,"risk_score":p.risk_score,"risk_level":p.risk_level,"prediction_time":p.prediction_time.isoformat(),"contributing_factors":json.loads(p.contributing_factors)} for p in rows]

@app.post("/api/predictions",response_model=PredictionOut)
def create_prediction(req:PredictionRequest,db:Session=Depends(get_db),user=Depends(current_user)):
    payload=req.model_dump()
    if req.device_id:
        d=db.get(Device,req.device_id)
        if not d: raise HTTPException(404,"Device not found")
        payload={k:getattr(d,k) for k in ["device_type","operating_system","failed_login_attempts","open_ports","total_vulnerabilities","critical_vulnerabilities","patch_age_days","network_anomaly_score","malware_alerts","privilege_escalation_attempts","previous_security_incidents"]}
        device_name=d.device_name
    else: device_name=req.device_name or "Custom Assessment"
    pred,score,probs=predict(payload)
    row={k:payload[k] for k in payload}
    factors=[]
    # Use transparent normalized indicator weights for display; these are not claimed to be causal.
    scales={"critical_vulnerabilities":3,"network_anomaly_score":100,"patch_age_days":90,"failed_login_attempts":15,"open_ports":10,"malware_alerts":3,"privilege_escalation_attempts":3,"previous_security_incidents":4,"total_vulnerabilities":10}
    ranked=[]
    for k,scale in scales.items(): ranked.append((min(float(payload[k])/scale,1.0),k))
    for value,k in sorted(ranked,reverse=True)[:5]: factors.append({"feature":FEATURE_LABELS[k],"importance":round(value,2),"value":payload[k]})
    recs=recommendations(payload)
    pred_row=None
    if req.device_id:
        pred_row=Prediction(device_id=req.device_id,risk_score=score,risk_level=pred,prediction_time=datetime.now(ZoneInfo("Asia/Kolkata")),contributing_factors=json.dumps(factors)); db.add(pred_row); db.commit(); db.refresh(pred_row)
    return {"id":pred_row.id if pred_row else None,"device_id":req.device_id,"device_name":device_name,"risk_score":score,"risk_level":pred,"prediction_time":pred_row.prediction_time.isoformat() if pred_row else datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(),"contributing_factors":factors,"recommendations":recs,"class_probabilities":probs}

@app.get("/api/predictions")
def predictions(db:Session=Depends(get_db),user=Depends(current_user)):
    rows=db.query(Prediction).order_by(Prediction.prediction_time.desc()).all()
    return [{"id":p.id,"device_id":p.device_id,"device_name":p.device.device_name,"risk_score":p.risk_score,"risk_level":p.risk_level,"prediction_time":p.prediction_time.isoformat(),"contributing_factors":json.loads(p.contributing_factors)} for p in rows]

@app.get("/api/model-performance")
def model_performance(user=Depends(current_user)): return METRICS
