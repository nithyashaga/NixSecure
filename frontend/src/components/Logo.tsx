import logo from '../assets/nixsecure-logo.png';
export default function Logo({small=false}:{small?:boolean}){return <div className="brand"><img src={logo} className={small?'brand-logo small':'brand-logo'}/><div><div className="brand-name">NIXSECURE</div>{!small&&<div className="brand-tag">Predict. Prioritize. Protect.</div>}</div></div>}
