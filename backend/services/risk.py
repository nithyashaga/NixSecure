FEATURE_LABELS = {
    "critical_vulnerabilities": "Critical vulnerabilities",
    "network_anomaly_score": "Network anomaly",
    "patch_age_days": "Patch age",
    "failed_login_attempts": "Failed login attempts",
    "open_ports": "Open ports",
    "malware_alerts": "Malware alerts",
    "privilege_escalation_attempts": "Privilege escalation attempts",
    "previous_security_incidents": "Previous security incidents",
    "total_vulnerabilities": "Total vulnerabilities",
}

def level(score: float) -> str:
    if score <= 30: return "LOW"
    if score <= 60: return "MEDIUM"
    return "HIGH"

def recommendations(row: dict):
    rec = []
    if row["critical_vulnerabilities"] > 0:
        rec.append("Prioritize patching critical vulnerabilities.")
    if row["patch_age_days"] > 30:
        rec.append("Review patch status and bring overdue systems up to date.")
    if row["failed_login_attempts"] >= 10:
        rec.append("Review authentication logs for repeated failed login attempts.")
    if row["network_anomaly_score"] >= 60:
        rec.append("Investigate unusual network activity and validate expected services.")
    if row["open_ports"] >= 8:
        rec.append("Review exposed services and close unnecessary ports.")
    if row["malware_alerts"] > 0:
        rec.append("Investigate endpoint/security alerts associated with this device.")
    if row["privilege_escalation_attempts"] > 0:
        rec.append("Review privilege changes and administrative activity.")
    if row["previous_security_incidents"] > 0:
        rec.append("Review previous incidents and verify remediation is complete.")
    if not rec:
        rec.append("Continue routine security monitoring and patch management.")
    return rec
