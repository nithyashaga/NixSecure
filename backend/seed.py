from database.db import Base, engine, SessionLocal
from models.entities import User, Device
from services.security import hash_password
from ml.train_model import train
from ml.predictor import predict
from services.risk import FEATURE_LABELS
import json
from datetime import datetime

def seed():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    if not db.query(User).filter_by(email="demo@nixsecure.local").first():
        db.add(User(name="NixSecure Demo",email="demo@nixsecure.local",password_hash=hash_password("NixSecure123")))
    if db.query(Device).count()==0:
        devices=[
          ("Finance-Laptop","Laptop","Windows 11","Finance","Active",12,8,6,2,45,67,1,2,3),
          ("HR-System","Desktop","Windows 11","Human Resources","Active",6,5,4,1,22,48,0,0,1),
          ("Server-01","Server","Ubuntu 24.04","Infrastructure","Active",2,3,2,0,12,22,0,0,0),
          ("Dev-PC-07","Workstation","Windows 11","Engineering","Active",15,10,8,3,61,74,1,3,2),
          ("Admin-Workstation","Workstation","Windows 11","IT","Active",8,7,5,1,35,55,0,1,2),
          ("Database-Server","Server","Ubuntu 24.04","Infrastructure","Active",3,4,3,1,28,34,0,0,1),
          ("Marketing-PC","Desktop","Windows 11","Marketing","Active",4,4,2,0,18,31,0,0,0),
          ("Sales-Laptop","Laptop","Windows 11","Sales","Active",9,6,5,1,39,59,0,1,1),
        ]
        for d in devices:
            db.add(Device(device_name=d[0],device_type=d[1],operating_system=d[2],department=d[3],status=d[4],failed_login_attempts=d[5],open_ports=d[6],total_vulnerabilities=d[7],critical_vulnerabilities=d[8],patch_age_days=d[9],network_anomaly_score=d[10],malware_alerts=d[11],privilege_escalation_attempts=d[12],previous_security_incidents=d[13]))
    db.commit()
    # Seed a small historical assessment trail so the dashboard is presentation-ready.
    from models.entities import Prediction
    if db.query(Prediction).count() == 0:
        for d in db.query(Device).limit(6).all():
            payload={k:getattr(d,k) for k in ["device_type","operating_system","failed_login_attempts","open_ports","total_vulnerabilities","critical_vulnerabilities","patch_age_days","network_anomaly_score","malware_alerts","privilege_escalation_attempts","previous_security_incidents"]}
            pred,score,_=predict(payload)
            scales={"critical_vulnerabilities":3,"network_anomaly_score":100,"patch_age_days":90,"failed_login_attempts":15,"open_ports":10,"malware_alerts":3,"privilege_escalation_attempts":3,"previous_security_incidents":4,"total_vulnerabilities":10}
            ranked=sorted([(min(float(payload[k])/scale,1.0),k) for k,scale in scales.items()],reverse=True)[:5]
            factors=[{"feature":FEATURE_LABELS[k],"importance":round(v,2),"value":payload[k]} for v,k in ranked]
            db.add(Prediction(device_id=d.id,risk_score=score,risk_level=pred,prediction_time=datetime.utcnow(),contributing_factors=json.dumps(factors)))
    db.commit(); db.close()

if __name__=="__main__":
    train(); seed(); print("NixSecure backend initialized. Demo login: demo@nixsecure.local / NixSecure123")
