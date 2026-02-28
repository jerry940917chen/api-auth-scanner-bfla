import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getProjects, startScan, getScan, getAuthMatrix } from '../api';
import { Shield, Play, X, RefreshCw, Table2, ChevronRight, AlertTriangle, CheckCircle2, HelpCircle } from 'lucide-react';

const STATUS_CONFIG = {
    vulnerable: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', label: '⚠ 漏洞', icon: '🔴' },
    allowed: { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', label: '✓ 可存取', icon: '🟡' },
    secure: { color: '#10b981', bg: 'rgba(16,185,129,0.12)', label: '✓ 安全', icon: '🟢' },
    unknown: { color: '#6b7280', bg: 'rgba(107,114,128,0.12)', label: '? 未知', icon: '⚪' },
};

function MatrixCell({ entry }) {
    const cfg = STATUS_CONFIG[entry?.status] || STATUS_CONFIG.unknown;
    return (
        <td style={{
            textAlign: 'center', padding: '10px 8px',
            background: cfg.bg,
            borderRight: '1px solid var(--border-subtle)',
        }}>
            <div style={{ fontSize: '1.1rem', lineHeight: 1 }}>{cfg.icon}</div>
            {entry?.vuln_type && (
                <div style={{ fontSize: '0.62rem', color: cfg.color, marginTop: 3, fontWeight: 600 }}>
                    {entry.vuln_type}
                </div>
            )}
        </td>
    );
}

export default function AuthMatrix() {
    const navigate = useNavigate();
    const [scans, setScans] = useState([]);
    const [projects, setProjects] = useState([]);
    const [selectedScanId, setSelectedScanId] = useState('');
    const [matrix, setMatrix] = useState(null);
    const [loading, setLoading] = useState(false);
    const [showNewScan, setShowNewScan] = useState(false);
    const [form, setForm] = useState({ projectId: '', token: '', role: 'user' });
    const [starting, setStarting] = useState(false);

    useEffect(() => {
        // Load completed scans from localStorage
        const stored = JSON.parse(localStorage.getItem('scanIds') || '[]');
        Promise.allSettled(stored.map(id =>
            fetch(`http://localhost:9000/scans/${id}`).then(r => r.json())
        )).then(results => {
            const completed = results
                .filter(r => r.status === 'fulfilled' && r.value.status === 'completed')
                .map(r => r.value);
            setScans(completed.reverse());
            if (completed.length > 0 && !selectedScanId) {
                setSelectedScanId(String(completed[0].id));
            }
        });

        fetch('http://localhost:9000/projects').then(r => r.json()).then(setProjects);
    }, []);

    useEffect(() => {
        if (!selectedScanId) return;
        setLoading(true);
        getAuthMatrix(selectedScanId)
            .then(setMatrix)
            .catch(console.error)
            .finally(() => setLoading(false));
    }, [selectedScanId]);

    const handleStartScan = async () => {
        if (!form.projectId || !form.token) return;
        setStarting(true);
        try {
            const result = await startScan(form.projectId, {
                profiles: [{ name: '測試用戶', role: form.role, token: form.token }]
            });
            const stored = JSON.parse(localStorage.getItem('scanIds') || '[]');
            localStorage.setItem('scanIds', JSON.stringify([...new Set([...stored, result.scan_id])]));
            setShowNewScan(false);
            alert(`掃描 #${result.scan_id} 已開始！掃描完成後在這裡查看 Auth Matrix。`);
        } catch (e) { alert('啟動失敗：' + e.message); }
        setStarting(false);
    };

    return (
        <>
            <div className="main-header">
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <div>
                        <h1 className="page-title">Auth Matrix <span style={{ fontSize: '0.65em', color: 'var(--accent-blue)', fontWeight: 500, marginLeft: 6 }}>BETA</span></h1>
                        <p className="page-subtitle">角色 × 端點 授權矩陣 — 視覺化每個角色能存取的 API 端點</p>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                        {scans.length > 0 && (
                            <select className="form-input" style={{ minWidth: 180 }} value={selectedScanId} onChange={e => setSelectedScanId(e.target.value)}>
                                {scans.map(s => (
                                    <option key={s.id} value={s.id}>Scan #{s.id} — {new Date(s.created_at).toLocaleDateString('zh-TW')}</option>
                                ))}
                            </select>
                        )}
                        <button className="btn btn-primary" onClick={() => setShowNewScan(true)}>
                            <Play size={14} /> 新掃描
                        </button>
                    </div>
                </div>
            </div>

            <div className="content-area">
                {/* Legend */}
                <div style={{ display: 'flex', gap: 16, marginBottom: 20, flexWrap: 'wrap' }}>
                    {Object.entries(STATUS_CONFIG).map(([key, cfg]) => (
                        <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 12px', background: cfg.bg, border: `1px solid ${cfg.color}40`, borderRadius: 'var(--radius-sm)' }}>
                            <span style={{ fontSize: '1rem' }}>{cfg.icon}</span>
                            <span style={{ fontSize: '0.78rem', color: cfg.color, fontWeight: 600 }}>{cfg.label}</span>
                        </div>
                    ))}
                </div>

                {/* Explanation card */}
                <div className="card" style={{ marginBottom: 20, borderColor: 'rgba(59,130,246,0.3)', background: 'rgba(59,130,246,0.04)' }}>
                    <div style={{ display: 'flex', gap: 12 }}>
                        <Table2 size={20} style={{ color: 'var(--accent-blue)', flexShrink: 0, marginTop: 2 }} />
                        <div>
                            <div style={{ fontWeight: 700, color: 'var(--text-heading)', marginBottom: 4 }}>Auth Matrix 是什麼？</div>
                            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
                                自動分析每個掃描角色（user / admin）對所有 API 端點的存取結果，找出「用低權限 token 能成功呼叫管理功能」的 BFLA 漏洞，以及跨用戶存取的 BOLA 漏洞。這是 Burp Suite / AppScan 做不到的授權邏輯分析。
                            </p>
                        </div>
                    </div>
                </div>

                {scans.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state-icon"><Shield size={48} /></div>
                        <h3>尚無已完成的掃描</h3>
                        <p>先建立並完成一次掃描，才能查看 Auth Matrix</p>
                        <button className="btn btn-primary" style={{ marginTop: 16, display: 'inline-flex' }} onClick={() => setShowNewScan(true)}>
                            <Play size={14} /> 開始掃描
                        </button>
                    </div>
                ) : loading ? (
                    <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>分析中...</div>
                ) : matrix ? (
                    <>
                        {/* Summary stats */}
                        <div className="stat-grid" style={{ marginBottom: 20 }}>
                            <div className="stat-card">
                                <div className="stat-card-value">{matrix.endpoints.length}</div>
                                <div className="stat-card-label">掃描端點數</div>
                            </div>
                            <div className="stat-card">
                                <div className="stat-card-value" style={{ color: 'var(--sev-high)' }}>
                                    {Object.values(matrix.matrix).filter(ep => Object.values(ep).some(r => r.status === 'vulnerable')).length}
                                </div>
                                <div className="stat-card-label">有漏洞的端點</div>
                            </div>
                            <div className="stat-card">
                                <div className="stat-card-value" style={{ color: 'var(--accent-green)' }}>
                                    {Object.values(matrix.matrix).filter(ep => Object.values(ep).every(r => r.status === 'secure')).length}
                                </div>
                                <div className="stat-card-label">安全端點</div>
                            </div>
                            <div className="stat-card">
                                <div className="stat-card-value">{matrix.roles.length}</div>
                                <div className="stat-card-label">測試角色數</div>
                            </div>
                        </div>

                        {/* Matrix table */}
                        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                            <div className="card-header" style={{ padding: '14px 20px' }}>
                                <span className="card-title">授權矩陣 — Scan #{matrix.scan_id}</span>
                                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                    {matrix.endpoints.length} 個端點 × {matrix.roles.length} 個角色
                                </span>
                            </div>
                            <div style={{ overflowX: 'auto' }}>
                                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                                    <thead>
                                        <tr style={{ background: 'var(--bg-primary)', borderBottom: '2px solid var(--border)' }}>
                                            <th style={{ textAlign: 'left', padding: '12px 20px', fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 700, minWidth: 250, borderRight: '1px solid var(--border)' }}>
                                                端點 (Endpoint)
                                            </th>
                                            {matrix.roles.map(role => (
                                                <th key={role} style={{ padding: '12px 20px', fontSize: '0.78rem', color: 'var(--text-primary)', fontWeight: 700, textAlign: 'center', minWidth: 120, borderRight: '1px solid var(--border-subtle)' }}>
                                                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                                                        <Shield size={14} style={{ color: 'var(--accent-blue)' }} />
                                                        {role}
                                                    </div>
                                                </th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {matrix.endpoints.map((ep, i) => {
                                            const epData = matrix.matrix[ep] || {};
                                            const hasVuln = Object.values(epData).some(r => r.status === 'vulnerable');
                                            return (
                                                <tr key={ep} style={{
                                                    borderBottom: '1px solid var(--border-subtle)',
                                                    background: hasVuln ? 'rgba(239,68,68,0.04)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                                                }}>
                                                    <td style={{ padding: '10px 20px', borderRight: '1px solid var(--border)', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem', color: hasVuln ? 'var(--sev-high)' : 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 280 }}>
                                                        {hasVuln && <AlertTriangle size={12} style={{ color: 'var(--sev-high)', marginRight: 6, display: 'inline' }} />}
                                                        {ep}
                                                    </td>
                                                    {matrix.roles.map(role => (
                                                        <MatrixCell key={role} entry={epData[role]} />
                                                    ))}
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </>
                ) : null}
            </div>

            {showNewScan && (
                <div className="modal-overlay" onClick={() => setShowNewScan(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <span className="modal-title">🚀 啟動 Auth Matrix 掃描</span>
                            <button className="btn btn-ghost btn-sm" onClick={() => setShowNewScan(false)}><X size={14} /></button>
                        </div>
                        <div className="form-group">
                            <label className="form-label">目標專案</label>
                            <select className="form-input" value={form.projectId} onChange={e => setForm({ ...form, projectId: e.target.value })}>
                                <option value="">選擇專案...</option>
                                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                        <div className="form-group">
                            <label className="form-label">Auth Token</label>
                            <input className="form-input mono" placeholder="eyJhbGciOiJIUzI1NiI..." value={form.token} onChange={e => setForm({ ...form, token: e.target.value })} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">角色</label>
                            <select className="form-input" value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
                                <option value="user">user（一般用戶）</option>
                                <option value="admin">admin（管理員）</option>
                            </select>
                        </div>
                        <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleStartScan} disabled={starting || !form.projectId || !form.token}>
                                {starting ? '啟動中...' : <><Play size={14} /> 開始掃描</>}
                            </button>
                            <button className="btn btn-ghost" onClick={() => setShowNewScan(false)}>取消</button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
