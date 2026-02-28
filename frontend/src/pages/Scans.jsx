import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getProjects, startScan, getScan } from '../api';
import { Shield, Play, X, RefreshCw, ChevronRight } from 'lucide-react';

const statusLabel = { completed: '完成', running: '掃描中', queued: '排隊中', failed: '失敗', canceled: '已取消' };
const statusBadge = { completed: 'success', running: 'running', queued: 'queued', failed: 'failed' };

export default function Scans() {
    const navigate = useNavigate();
    const [scans, setScans] = useState([]);
    const [projects, setProjects] = useState([]);
    const [showNew, setShowNew] = useState(false);
    const [form, setForm] = useState({
        projectId: '',
        tokenA: '', roleA: 'user', nameA: 'UserA',
        tokenB: '', roleB: 'user', nameB: 'UserB',
        bolaPaths: '/api/v1/users,/api/v1/books',
        customHeaders: '{"X-Forwarded-For": "127.0.0.1"}',
        authBypass: true
    });
    const [starting, setStarting] = useState(false);
    const [liveIds, setLiveIds] = useState(new Set());

    useEffect(() => {
        fetchAll();
        const interval = setInterval(pollLive, 3000);
        return () => clearInterval(interval);
    }, []);

    const fetchAll = async () => {
        try {
            const projs = await getProjects();
            setProjects(projs);
            const stored = JSON.parse(localStorage.getItem('scanIds') || '[]');
            const results = await Promise.allSettled(stored.map(id => getScan(id)));
            const loaded = results.filter(r => r.status === 'fulfilled').map(r => r.value);
            setScans(loaded.reverse());
            setLiveIds(new Set(loaded.filter(s => s.status === 'running' || s.status === 'queued').map(s => s.id)));
        } catch (_) { }
    };

    const pollLive = async () => {
        setLiveIds(prev => {
            if (!prev.size) return prev;
            prev.forEach(async id => {
                try {
                    const scan = await getScan(id);
                    if (scan.status === 'completed' || scan.status === 'failed') {
                        setLiveIds(p => { const n = new Set(p); n.delete(id); return n; });
                        setScans(p => p.map(s => s.id === id ? scan : s));
                    }
                } catch (_) { }
            });
            return prev;
        });
    };

    const handleStart = async () => {
        if (!form.projectId || !form.tokenA) return;
        setStarting(true);
        try {
            const profiles = [{ name: form.nameA, role: form.roleA, token: form.tokenA }];
            if (form.tokenB) {
                profiles.push({ name: form.nameB, role: form.roleB, token: form.tokenB });
            }

            let customHeadersObj = {};
            try { customHeadersObj = JSON.parse(form.customHeaders || '{}'); } catch (e) { }

            const result = await startScan(form.projectId, {
                profiles: profiles,
                scan_options: {
                    bola_extraction_paths: form.bolaPaths.split(',').map(p => p.trim()).filter(Boolean),
                    custom_headers: customHeadersObj,
                    auth_bypass_techniques: form.authBypass
                }
            });
            const stored = JSON.parse(localStorage.getItem('scanIds') || '[]');
            localStorage.setItem('scanIds', JSON.stringify([...new Set([...stored, result.scan_id])]));
            setShowNew(false);
            setForm({ ...form, projectId: '', tokenA: '', tokenB: '' });
            setLiveIds(prev => new Set([...prev, result.scan_id]));
            setTimeout(fetchAll, 800);
        } catch (e) { alert('啟動失敗：' + e.message); }
        setStarting(false);
    };

    const sorted = [...scans].sort((a, b) => {
        const order = { running: 0, queued: 1, completed: 2, failed: 3 };
        return (order[a.status] ?? 9) - (order[b.status] ?? 9);
    });

    return (
        <>
            <div className="main-header">
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <div>
                        <h1 className="page-title">掃描任務</h1>
                        <p className="page-subtitle">執行並監控所有 API 安全掃描任務</p>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                        <button className="btn btn-ghost" onClick={fetchAll}><RefreshCw size={14} /> 重新整理</button>
                        <button className="btn btn-primary" onClick={() => setShowNew(true)}><Play size={14} /> 新掃描</button>
                    </div>
                </div>
            </div>

            <div className="content-area">
                {sorted.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state-icon"><Shield size={48} /></div>
                        <h3>尚無掃描任務</h3>
                        <p>建立掃描以檢測 OWASP API Top 10 漏洞</p>
                        <button className="btn btn-primary" style={{ marginTop: 16, display: 'inline-flex' }} onClick={() => setShowNew(true)}>
                            <Play size={14} /> 建立第一次掃描
                        </button>
                    </div>
                ) : (
                    <div className="card" style={{ padding: 0 }}>
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>掃描 ID</th><th>狀態</th><th>漏洞數</th><th>嚴重性分佈</th><th>建立時間</th><th></th>
                                </tr>
                            </thead>
                            <tbody>
                                {sorted.map(s => (
                                    <tr key={s.id} onClick={() => navigate(`/scans/${s.id}`)}>
                                        <td><span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 600, color: 'var(--text-primary)' }}>#{s.id}</span></td>
                                        <td>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                <span className={`status-dot ${s.status}`} />
                                                <span className={`badge badge-${statusBadge[s.status] || s.status}`}>{statusLabel[s.status] || s.status}</span>
                                            </div>
                                        </td>
                                        <td><span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{s.vulnerabilities?.length ?? '—'}</span></td>
                                        <td>
                                            <div style={{ display: 'flex', gap: 6 }}>
                                                {s.summary_counts?.High > 0 && <span className="badge badge-high">高:{s.summary_counts.High}</span>}
                                                {s.summary_counts?.Medium > 0 && <span className="badge badge-medium">中:{s.summary_counts.Medium}</span>}
                                                {s.summary_counts?.Low > 0 && <span className="badge badge-low">低:{s.summary_counts.Low}</span>}
                                            </div>
                                        </td>
                                        <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{new Date(s.created_at).toLocaleString('zh-TW')}</td>
                                        <td><ChevronRight size={14} style={{ color: 'var(--text-muted)' }} /></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {showNew && (
                <div className="modal-overlay" onClick={() => setShowNew(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <span className="modal-title">🚀 新安全掃描</span>
                            <button className="btn btn-ghost btn-sm" onClick={() => setShowNew(false)}><X size={14} /></button>
                        </div>
                        <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '10px 14px', marginBottom: 20, fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                            🛡️ 涵蓋完整 <strong style={{ color: 'var(--text-primary)' }}>OWASP API Top 10</strong> 檢測，包含 BFLA、BOLA、SSRF、驗證繞過等
                        </div>
                        <div className="form-group">
                            <label className="form-label">目標專案</label>
                            <select className="form-input" value={form.projectId} onChange={e => setForm({ ...form, projectId: e.target.value })}>
                                <option value="">選擇專案...</option>
                                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                        <div className="form-group">
                            <label className="form-label" style={{ fontWeight: 'bold' }}>主要測試用戶 (Profile A)</label>
                            <input className="form-input mono" placeholder="Token A (e.g. eyJhbG...)" value={form.tokenA} onChange={e => setForm({ ...form, tokenA: e.target.value })} style={{ marginBottom: 4 }} />
                            <div style={{ display: 'flex', gap: 8 }}>
                                <input className="form-input" placeholder="名稱" value={form.nameA} onChange={e => setForm({ ...form, nameA: e.target.value })} style={{ flex: 1 }} />
                                <select className="form-input" value={form.roleA} onChange={e => setForm({ ...form, roleA: e.target.value })} style={{ flex: 1 }}>
                                    <option value="user">一般用戶</option><option value="admin">管理員</option>
                                </select>
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label" style={{ fontWeight: 'bold' }}>跨用戶 BOLA 測試 (Profile B) - 選填</label>
                            <input className="form-input mono" placeholder="Token B" value={form.tokenB} onChange={e => setForm({ ...form, tokenB: e.target.value })} style={{ marginBottom: 4 }} />
                            <div style={{ display: 'flex', gap: 8 }}>
                                <input className="form-input" placeholder="名稱" value={form.nameB} onChange={e => setForm({ ...form, nameB: e.target.value })} style={{ flex: 1 }} />
                                <select className="form-input" value={form.roleB} onChange={e => setForm({ ...form, roleB: e.target.value })} style={{ flex: 1 }}>
                                    <option value="user">一般用戶</option><option value="admin">管理員</option>
                                </select>
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">進階設定: BOLA ID 提取路徑 (逗號分隔)</label>
                            <input className="form-input mono" placeholder="/api/v1/users, /api/v1/posts" value={form.bolaPaths} onChange={e => setForm({ ...form, bolaPaths: e.target.value })} />
                            <small style={{ color: 'var(--text-muted)' }}>從這些路徑爬取資源 ID，用於跨用戶 ID 取代測試。</small>
                        </div>

                        <div className="form-group">
                            <label className="form-label">進階設定: 自訂 Headers (JSON)</label>
                            <input className="form-input mono" placeholder='{"X-Forwarded-For": "127.0.0.1"}' value={form.customHeaders} onChange={e => setForm({ ...form, customHeaders: e.target.value })} />
                        </div>

                        <div className="form-group" style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12 }}>
                            <input type="checkbox" id="authBypass" checked={form.authBypass} onChange={e => setForm({ ...form, authBypass: e.target.checked })} />
                            <label htmlFor="authBypass" style={{ color: 'var(--text-primary)', fontSize: '0.85rem' }}>啟用進階身份驗證繞過測試 (Auth Bypass)</label>
                        </div>
                        <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
                            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleStart} disabled={starting || !form.projectId || !form.tokenA}>
                                {starting ? '啟動中...' : <><Play size={14} /> 開始進階企業掃描</>}
                            </button>
                            <button className="btn btn-ghost" onClick={() => setShowNew(false)}>取消</button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
