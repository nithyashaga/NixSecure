export default function RiskBadge({risk}:{risk:string}){return <span className={`risk-badge ${risk.toLowerCase()}`}>{risk}</span>}
