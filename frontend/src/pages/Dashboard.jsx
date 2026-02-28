import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getProjects, startScan, getScan } from '../api';
import {
    Shield, AlertTriangle, CheckCircle2, Clock, TrendingUp,
    BarChart2, Play, X
} from 'lucide-react';
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts';

const OWASP_COLORS = {
    'BFLA': '#ef4444',
    'BOLA': '#f97316',
    'Mass Assignment': '#f59e0b',
    'Rate Limiting': '#eab308',
    'Data Exposure': '#a855f7',
    'CORS Misconfiguration': '#3b82f6',
    'Missing Security Headers': '#06b6d4',
    'Verbose Error Exposure': '#10b981',
    'Improper Inventory Management': '#6366f1',
    'Broken Authentication': '#ec4899',
};

function SeverityPill({ severity }) {
    const map = { High: '高危', Medium: '中危', Low: '低危' };
    const cls = severity === 'High' ? 'badge-high' : severity === 'Medium' ? 'badge-medium' : 'badge-low';
    return <span className={`badge ${cls}`}>{map[severity] || severity}</span>;
}

export default function Dashboard() {
    const navigate = useNavigate();
    const [projects, setProjects] = useState([]);
    const [scans, setScans] = useState([]);
    const [showNewScan, setShowNewScan] = useState(false);
    const [selectedProjectId, setSelectedProjectId] = useState('');
    const [scanToken, setScanToken] = useState('');
    const [scanning, setScanning] = useState(false);
    const [liveScans, setLiveScans] = useState({});

    useEffect(() => { fetchData(); }, []);

    const fetchData = async () => {
        try {
            const projs = await getProjects();
            setProjects(projs);
            const stored = JSON.parse(localStorage.getItem('scanIds') || '[]');
            const scanResults = await Promise.allSettled(stored.map(id => getScan(id)));
            setScans(scanResults.filter(r => r.status === 'fulfilled').map(r => r.value));
        } catch (_) { }
    };

    useEffect(() => {
        const interval = setInterval(async () => {
            const ids = Object.keys(liveScans);
            if (!ids.length) return;
            for (const id of ids) {
                try {
                    const scan = await getScan(id);
                    if (scan.status === 'completed' || scan.status === 'failed') {
                        setLiveScans(prev => { const n = { ...prev }; delete n[id]; return n; });
                        setScans(prev => {
                            const exists = prev.find(s => s.id === scan.id);
                            return exists ? prev.map(s => s.id === scan.id ? scan : s) : [scan, ...prev];
                        });
                    }
                } catch (_) { }
            }
        }, 3000);
        return () => clearInterval(interval);
    }, [liveScans]);

    const handleStartScan = async () => {
        if (!selectedProjectId || !scanToken) return;
        setScanning(true);
        try {
            const result = await startScan(selectedProjectId, {
                profiles: [{ name: '測試用戶', role: 'user', token: scanToken }]
            });
            setLiveScans(prev => ({ ...prev, [result.scan_id]: true }));
            const stored = JSON.parse(localStorage.getItem('scanIds') || '[]');
            localStorage.setItem('scanIds', JSON.stringify([...new Set([...stored, result.scan_id])]));
            setShowNewScan(false);
            setScanToken('');
        } catch (e) { alert('啟動掃描失敗：' + e.message); }
        setScanning(false);
    };

    const completedScans = scans.filter(s => s.status === 'completed');
    const totalVulns = completedScans.reduce((acc, s) => acc + (s.vulnerabilities?.length || 0), 0);
    const highVulns = completedScans.reduce((acc, s) => acc + (s.summary_counts?.High || 0), 0);
    const vulnTypeCounts = {};
    completedScans.forEach(s => (s.vulnerabilities || []).forEach(v => {
        vulnTypeCounts[v.vuln_type] = (vulnTypeCounts[v.vuln_type] || 0) + 1;
    }));
    const chartData = Object.entries(vulnTypeCounts).map(([name, count]) => ({ name, count }));
    const recentVulns = completedScans.flatMap(s => s.vulnerabilities || []).slice(0, 6);

    const statusLabel = { completed: '完成', running: '掃描中', queued: '排隊中', failed: '失敗', canceled: '已取消' };

    return (
        <>
            <div className="main-header">
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <div>
                        <h1 className="page-title">安全掃描總覽</h1>
                        <p className="page-subtitle">所有 API 安全掃描結果的綜合視圖</p>
                    </div>
                    <button className="btn btn-primary" onClick={() => setShowNewScan(true)}>
                        <Play size={14} /> 快速掃描
                    </button>
                </div>
            </div>

            <div className="content-area">
                <div className="stat-grid">
                    <div className="stat-card">
                        <div className="stat-card-icon" style={{ background: 'rgba(59,130,246,0.15)' }}>
                            <Shield size={18} style={{ color: 'var(--accent-blue)' }} />
                        </div>
                        <div className="stat-card-value">{scans.length}</div>
                        <div className="stat-card-label">掃描總次數</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-card-icon" style={{ background: 'rgba(239,68,68,0.15)' }}>
                            <AlertTriangle size={18} style={{ color: 'var(--sev-high)' }} />
                        </div>
                        <div className="stat-card-value" style={{ color: 'var(--sev-high)' }}>{highVulns}</div>
                        <div className="stat-card-label">高危漏洞</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-card-icon" style={{ background: 'rgba(16,185,129,0.15)' }}>
                            <CheckCircle2 size={18} style={{ color: 'var(--accent-green)' }} />
                        </div>
                        <div className="stat-card-value" style={{ color: 'var(--accent-green)' }}>{completedScans.length}</div>
                        <div className="stat-card-label">已完成掃描</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-card-icon" style={{ background: 'rgba(139,92,246,0.15)' }}>
                            <TrendingUp size={18} style={{ color: 'var(--accent-purple)' }} />
                        </div>
                        <div className="stat-card-value">{projects.length}</div>
                        <div className="stat-card-label">管理專案數</div>
                    </div>
                </div>

                {Object.keys(liveScans).length > 0 && (
                    <div className="card" style={{ marginBottom: 20, borderColor: 'var(--accent-blue)', borderLeftWidth: 3 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                            <span className="status-dot running" />
                            <span style={{ fontWeight: 600, color: 'var(--text-heading)' }}>
                                {Object.keys(liveScans).length} 個掃描進行中...
                            </span>
                            <div className="progress-bar" style={{ flex: 1 }}><div className="progress-fill" /></div>
                        </div>
                    </div>
                )}

                <div className="grid-2">
                    <div className="card">
                        <div className="card-header">
                            <span className="card-title">漏洞類型分佈</span>
                            <BarChart2 size={16} style={{ color: 'var(--text-muted)' }} />
                        </div>
                        {chartData.length > 0 ? (
                            <div className="chart-container">
                                <ResponsiveContainer width="100%" height="100%">
                                    <BarChart data={chartData} margin={{ top: 0, right: 0, bottom: 20, left: -20 }}>
                                        <XAxis dataKey="name" tick={{ fontSize: 9, fill: 'var(--text-muted)', angle: -30, textAnchor: 'end' }} />
                                        <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} allowDecimals={false} />
                                        <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)', fontSize: 12 }} />
                                        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                                            {chartData.map((entry, i) => (
                                                <Cell key={i} fill={OWASP_COLORS[entry.name] || '#3b82f6'} />
                                            ))}
                                        </Bar>
                                    </BarChart>
                                </ResponsiveContainer>
                            </div>
                        ) : (
                            <div className="empty-state" style={{ padding: '40px 20px' }}>
                                <div className="empty-state-icon"><BarChart2 size={32} /></div>
                                <p>執行第一次掃描後就會顯示統計圖表</p>
                            </div>
                        )}
                    </div>

                    <div className="card">
                        <div className="card-header">
                            <span className="card-title">最新發現</span>
                            <AlertTriangle size={16} style={{ color: 'var(--text-muted)' }} />
                        </div>
                        {recentVulns.length > 0 ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                {recentVulns.map((v, i) => (
                                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px', background: 'var(--bg-primary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                                        <SeverityPill severity={v.severity} />
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{v.vuln_type}</div>
                                            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: 'JetBrains Mono, monospace' }}>{v.endpoint}</div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="empty-state" style={{ padding: '40px 20px' }}>
                                <div className="empty-state-icon"><CheckCircle2 size={32} /></div>
                                <p>尚無漏洞資料</p>
                            </div>
                        )}
                    </div>
                </div>

                {scans.length > 0 && (
                    <div className="card" style={{ marginTop: 20 }}>
                        <div className="card-header"><span className="card-title">最近掃描記錄</span></div>
                        <table className="data-table">
                            <thead>
                                <tr><th>掃描 ID</th><th>狀態</th><th>漏洞數</th><th>高危</th><th>建立時間</th></tr>
                            </thead>
                            <tbody>
                                {scans.slice(0, 5).map(s => (
                                    <tr key={s.id} onClick={() => navigate(`/scans/${s.id}`)}>
                                        <td style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-primary)' }}>#{s.id}</td>
                                        <td>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                <span className={`status-dot ${s.status}`} />
                                                <span className={`badge badge-${s.status === 'completed' ? 'success' : s.status}`}>{statusLabel[s.status] || s.status}</span>
                                            </div>
                                        </td>
                                        <td>{s.vulnerabilities?.length ?? '-'}</td>
                                        <td style={{ color: 'var(--sev-high)', fontWeight: 600 }}>{s.summary_counts?.High ?? 0}</td>
                                        <td style={{ fontSize: '0.8rem' }}>{new Date(s.created_at).toLocaleString('zh-TW')}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {showNewScan && (
                <div className="modal-overlay" onClick={() => setShowNewScan(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <span className="modal-title">🚀 啟動新掃描</span>
                            <button className="btn btn-ghost btn-sm" onClick={() => setShowNewScan(false)}><X size={14} /></button>
                        </div>
                        <div className="form-group">
                            <label className="form-label">目標專案</label>
                            <select className="form-input" value={selectedProjectId} onChange={e => setSelectedProjectId(e.target.value)}>
                                <option value="">選擇專案...</option>
                                {projects.map(p => <option key={p.id} value={p.id}>{p.name} ({p.base_url})</option>)}
                            </select>
                        </div>
                        <div className="form-group">
                            <label className="form-label">測試用戶 Token</label>
                            <input className="form-input mono" type="text" placeholder="eyJhbGciOi..." value={scanToken} onChange={e => setScanToken(e.target.value)} />
                        </div>
                        <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleStartScan} disabled={scanning || !selectedProjectId || !scanToken}>
                                {scanning ? '啟動中...' : <><Play size={14} /> 開始掃描</>}
                            </button>
                            <button className="btn btn-ghost" onClick={() => setShowNewScan(false)}>取消</button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
