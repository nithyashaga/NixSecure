import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  BrainCircuit,
  ShieldAlert,
  Clock3,
  Network,
  KeyRound,
  Bug,
  AlertTriangle,
} from 'lucide-react';

import { api, Device, Prediction } from '../services/api';
import RiskBadge from '../components/RiskBadge';
import ScoreRing from '../components/ScoreRing';

export default function DeviceDetails() {
  const { id } = useParams();
  const nav = useNavigate();

  const [d, setD] = useState<Device | null>(null);
  const [result, setResult] = useState<Prediction | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (id) {
      api.device(Number(id)).then(setD);
    }
  }, [id]);

  if (!d) {
    return (
      <div className="loading-screen">
        Loading device profile…
      </div>
    );
  }

  // Store the narrowed non-null device object.
  // This prevents TypeScript from complaining that `d` may be null
  // inside the async predict function.
  const device = d;

  async function predict() {
    setLoading(true);
    setError('');

    try {
      const r = await api.predict({
        device_id: device.id,
        device_type: device.device_type,
        operating_system: device.operating_system,
        failed_login_attempts: device.failed_login_attempts,
        open_ports: device.open_ports,
        total_vulnerabilities: device.total_vulnerabilities,
        critical_vulnerabilities: device.critical_vulnerabilities,
        patch_age_days: device.patch_age_days,
        network_anomaly_score: device.network_anomaly_score,
        malware_alerts: device.malware_alerts,
        privilege_escalation_attempts:
          device.privilege_escalation_attempts,
        previous_security_incidents:
          device.previous_security_incidents,
      });

      setResult(r);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : 'Prediction failed'
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <button
        className="back-inline"
        onClick={() => nav('/app/devices')}
      >
        <ArrowLeft size={16} />
        Back to devices
      </button>

      <div className="device-head">
        <div>
          <div className="eyebrow">
            DEVICE PROFILE / {device.id.toString().padStart(3, '0')}
          </div>

          <h1>{device.device_name}</h1>

          <p>
            {device.department} · {device.device_type} ·{' '}
            {device.operating_system}
          </p>
        </div>

        <div className="device-status">
          <span className="status-dot" /> {device.status}
        </div>
      </div>

      <div className="info-banner">
        <BrainCircuit size={20} />

        <div>
          <b>Assessment is manual.</b>

          <span>
            NixSecure will not automatically predict this device.
            Review the stored indicators below, then choose when to
            run the AI assessment.
          </span>
        </div>
      </div>

      <div className="indicator-grid">
        {[
          [
            'Failed login attempts',
            device.failed_login_attempts,
            KeyRound,
          ],
          ['Open ports', device.open_ports, Network],
          [
            'Total vulnerabilities',
            device.total_vulnerabilities,
            ShieldAlert,
          ],
          [
            'Critical vulnerabilities',
            device.critical_vulnerabilities,
            AlertTriangle,
          ],
          [
            'Patch age',
            `${device.patch_age_days} days`,
            Clock3,
          ],
          [
            'Network anomaly',
            `${device.network_anomaly_score}/100`,
            Network,
          ],
          ['Malware alerts', device.malware_alerts, Bug],
          [
            'Privilege escalations',
            device.privilege_escalation_attempts,
            ShieldAlert,
          ],
          [
            'Previous incidents',
            device.previous_security_incidents,
            AlertTriangle,
          ],
        ].map(([label, value, Icon]: any) => (
          <div className="indicator" key={label}>
            <Icon size={17} />
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>

      <div className="predict-bar">
        <div>
          <div className="eyebrow">AI RISK ASSESSMENT</div>

          <h3>Ready when you are.</h3>

          <p>
            Use the stored security profile as the model input.
          </p>
        </div>

        <button
          className="primary-btn predict-btn"
          onClick={predict}
          disabled={loading}
        >
          <BrainCircuit size={18} />

          {loading
            ? 'Analyzing…'
            : 'Predict Cybersecurity Risk'}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-grid">
          <section className="panel result-main">
            <div className="panel-head">
              <div>
                <span className="eyebrow">MODEL OUTPUT</span>

                <h3>AI risk prediction</h3>
              </div>

              <RiskBadge risk={result.risk_level} />
            </div>

            <div className="result-score">
              <ScoreRing
                score={result.risk_score}
                risk={result.risk_level}
              />

              <div>
                <div className="result-score-label">
                  Predicted posture
                </div>

                <h2>{result.risk_level} RISK</h2>

                <p>
                  NixSecure's Random Forest model assessed the
                  stored security profile and generated this
                  prototype risk score.
                </p>
              </div>
            </div>

            <div className="probabilities">
              {result.class_probabilities &&
                Object.entries(result.class_probabilities).map(
                  ([k, v]) => (
                    <div key={k}>
                      <span>{k}</span>

                      <div className="prob-bar">
                        <i
                          style={{
                            width: `${Number(v) * 100}%`,
                          }}
                        />
                      </div>

                      <b>
                        {Math.round(Number(v) * 100)}%
                      </b>
                    </div>
                  )
                )}
            </div>
          </section>

          <section className="panel">
            <div className="eyebrow">WHY THIS RISK?</div>

            <h3>Key contributing indicators</h3>

            <div className="factor-list">
              {result.contributing_factors.map((f) => (
                <div className="factor" key={f.feature}>
                  <div>
                    <b>{f.feature}</b>

                    <span>
                      Observed value: {f.value}
                    </span>
                  </div>

                  <div className="factor-bar">
                    <i
                      style={{
                        width: `${Math.max(
                          8,
                          f.importance * 100
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="panel recommendations">
            <div className="eyebrow">
              PRIORITIZED RESPONSE
            </div>

            <h3>Recommended actions</h3>

            {result.recommendations.map((x, i) => (
              <div className="recommendation" key={i}>
                <span>
                  {String(i + 1).padStart(2, '0')}
                </span>

                <p>{x}</p>
              </div>
            ))}
          </section>
        </div>
      )}
    </div>
  );
}