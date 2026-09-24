const API='http://localhost:8000/api';
export type Device={id:number;device_name:string;device_type:string;operating_system:string;department:string;status:string;failed_login_attempts:number;open_ports:number;total_vulnerabilities:number;critical_vulnerabilities:number;patch_age_days:number;network_anomaly_score:number;malware_alerts:number;privilege_escalation_attempts:number;previous_security_incidents:number;created_at:string};
export type Prediction={id?:number;device_id?:number;device_name:string;risk_score:number;risk_level:string;prediction_time:string;contributing_factors:{feature:string;importance:number;value:number}[];recommendations:string[];class_probabilities?:Record<string,number>};
async function request(path:string, options:RequestInit={}) {
    const token = localStorage.getItem('nix_token');

    const headers = new Headers(options.headers);
    headers.set('Content-Type', 'application/json');

    if (token) {
        headers.set('Authorization', `Bearer ${token}`);
    }

    const res = await fetch(API + path, {
        ...options,
        headers
    });

    const data = await res.json().catch(() => ({
        detail: 'Unexpected server response'
    }));

    if (res.status === 401) {
        localStorage.removeItem('nix_token');
        localStorage.removeItem('nix_user');

        if (window.location.pathname !== '/login') {
            window.location.href = '/login';
        }

        throw new Error(
            typeof data.detail === 'string'
                ? data.detail
                : 'Your session has expired. Please sign in again.'
        );
    }

    if (!res.ok) {
        const detail = data?.detail;

        const message =
            typeof detail === 'string'
                ? detail
                : Array.isArray(detail)
                    ? detail.map((item:any) =>
                        typeof item === 'object'
                            ? (item.msg || item.message || JSON.stringify(item))
                            : String(item)
                    ).join(', ')
                    : detail && typeof detail === 'object'
                        ? (detail.msg || detail.message || JSON.stringify(detail))
                        : 'Request failed';

        throw new Error(message);
    }

    return data;
}
export const api={
 login:(email:string,password:string)=>request('/auth/login',{method:'POST',body:JSON.stringify({email,password})}),
 register:(name:string,email:string,password:string)=>request('/auth/register',{method:'POST',body:JSON.stringify({name,email,password})}),
 guest:()=>request('/auth/guest',{method:'POST'}),
 me:()=>request('/me'),
 dashboard:()=>request('/dashboard'),
 devices:()=>request('/devices'),
 device:(id:number)=>request(`/devices/${id}`),
 predict:(payload:unknown)=>request('/predictions',{method:'POST',body:JSON.stringify(payload)}),
 predictions:()=>request('/predictions'),
 modelPerformance:()=>request('/model-performance')
};
