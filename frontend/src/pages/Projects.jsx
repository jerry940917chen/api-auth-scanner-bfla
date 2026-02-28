import React, { useState, useEffect } from 'react';
import { getProjects, createProject, deleteProject } from '../api';
import { FolderOpen, Plus, X, Globe, Link, ExternalLink, Trash2 } from 'lucide-react';

export default function Projects() {
    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showCreate, setShowCreate] = useState(false);
    const [form, setForm] = useState({ name: '', base_url: '', openapi_url: '' });
    const [creating, setCreating] = useState(false);
    const [deleting, setDeleting] = useState(null);

    useEffect(() => { fetchProjects(); }, []);

    const fetchProjects = async () => {
        try {
            const data = await getProjects();
            setProjects(data);
        } catch (e) { console.error(e); }
        setLoading(false);
    };

    const handleCreate = async () => {
        if (!form.name || !form.base_url) return;
        setCreating(true);
        try {
            await createProject(form);
            await fetchProjects();
            setShowCreate(false);
            setForm({ name: '', base_url: '', openapi_url: '' });
        } catch (e) { alert('建立專案失敗：' + e.message); }
        setCreating(false);
    };

    const handleDelete = async (p) => {
        if (!window.confirm(`確定要刪除專案「${p.name}」(#${p.id})？\n此操作無法復原。`)) return;
        setDeleting(p.id);
        try {
            await deleteProject(p.id);
            setProjects(prev => prev.filter(x => x.id !== p.id));
        } catch (e) { alert('刪除失敗：' + e.message); }
        setDeleting(null);
    };

    return (
        <>
            <div className="main-header">
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <div>
                        <h1 className="page-title">專案管理</h1>
                        <p className="page-subtitle">管理掃描目標 API 的設定與端點</p>
                    </div>
                    <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
                        <Plus size={14} /> 新增專案
                    </button>
                </div>
            </div>

            <div className="content-area">
                {loading ? (
                    <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>載入中...</div>
                ) : projects.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state-icon"><FolderOpen size={48} /></div>
                        <h3>目前沒有任何專案</h3>
                        <p>建立第一個專案以開始掃描 API。</p>
                        <button className="btn btn-primary" style={{ margin: '16px auto 0', display: 'inline-flex' }} onClick={() => setShowCreate(true)}>
                            <Plus size={14} /> 建立專案
                        </button>
                    </div>
                ) : (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
                        {projects.map(p => (
                            <div key={p.id} className="card" style={{ cursor: 'default', transition: 'var(--transition)', position: 'relative' }}
                                onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accent-blue)'}
                                onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
                            >
                                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
                                    <div style={{
                                        width: 40, height: 40,
                                        background: 'var(--accent-blue-dim)',
                                        borderRadius: 'var(--radius-sm)',
                                        display: 'flex', alignItems: 'center', justifyContent: 'center'
                                    }}>
                                        <Globe size={18} style={{ color: 'var(--accent-blue)' }} />
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>#{p.id}</span>
                                        <button
                                            className="btn btn-danger btn-sm"
                                            style={{ padding: '4px 8px' }}
                                            onClick={() => handleDelete(p)}
                                            disabled={deleting === p.id}
                                            title="刪除此專案"
                                        >
                                            <Trash2 size={12} />
                                        </button>
                                    </div>
                                </div>
                                <h3 style={{ fontWeight: 700, color: 'var(--text-heading)', marginBottom: 6 }}>{p.name}</h3>
                                <a
                                    href={p.base_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8rem', color: 'var(--accent-blue)', textDecoration: 'none', marginBottom: 4 }}
                                >
                                    <Link size={11} />
                                    {p.base_url}
                                    <ExternalLink size={10} />
                                </a>
                                {p.openapi_url && (
                                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 12 }}>
                                        OpenAPI: {p.openapi_url}
                                    </div>
                                )}
                                <hr className="separator" style={{ margin: '12px 0' }} />
                                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                    建立於 {new Date(p.created_at).toLocaleDateString('zh-TW')}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Create Modal */}
            {showCreate && (
                <div className="modal-overlay" onClick={() => setShowCreate(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <span className="modal-title">➕ 新增專案</span>
                            <button className="btn btn-ghost btn-sm" onClick={() => setShowCreate(false)}><X size={14} /></button>
                        </div>
                        <div className="form-group">
                            <label className="form-label">專案名稱</label>
                            <input className="form-input" placeholder="Demo API" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Base URL</label>
                            <input className="form-input mono" placeholder="http://demo_api:8000" value={form.base_url} onChange={e => setForm({ ...form, base_url: e.target.value })} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">OpenAPI 規格 URL <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>(選填)</span></label>
                            <input className="form-input mono" placeholder="http://demo_api:8000/openapi.json" value={form.openapi_url} onChange={e => setForm({ ...form, openapi_url: e.target.value })} />
                        </div>
                        <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                            <button
                                className="btn btn-primary"
                                style={{ flex: 1 }}
                                onClick={handleCreate}
                                disabled={creating || !form.name || !form.base_url}
                            >
                                {creating ? '建立中...' : <><Plus size={14} /> 建立專案</>}
                            </button>
                            <button className="btn btn-ghost" onClick={() => setShowCreate(false)}>取消</button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
