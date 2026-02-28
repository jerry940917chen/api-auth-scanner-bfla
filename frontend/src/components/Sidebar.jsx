import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FolderOpen, Shield, FileText, Activity, FlaskConical, Table2 } from 'lucide-react';

const navItems = [
    { to: '/', icon: <LayoutDashboard size={16} />, label: '總覽' },
    { to: '/projects', icon: <FolderOpen size={16} />, label: '專案管理' },
    { to: '/scans', icon: <Shield size={16} />, label: '掃描任務' },
    { to: '/reports', icon: <FileText size={16} />, label: '報告下載' },
    { to: '/auth-matrix', icon: <Table2 size={16} />, label: 'Auth Matrix', badge: 'NEW' },
    { to: '/testcases', icon: <FlaskConical size={16} />, label: '測試項目清單' },
];

export default function Sidebar() {
    return (
        <aside className="sidebar">
            <div className="sidebar-logo">
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{
                        width: 32, height: 32,
                        background: 'linear-gradient(135deg, #3b82f6, #06b6d4)',
                        borderRadius: 8,
                        display: 'flex', alignItems: 'center', justifyContent: 'center'
                    }}>
                        <Shield size={16} color="#fff" />
                    </div>
                    <div>
                        <div className="sidebar-logo-text">API 安全掃描器</div>
                        <div className="sidebar-logo-badge">BFLA · OWASP Top 10</div>
                    </div>
                </div>
            </div>

            <nav className="sidebar-nav">
                <div className="sidebar-section-label">導覽</div>
                {navItems.map(({ to, icon, label }) => (
                    <NavLink
                        key={to}
                        to={to}
                        end={to === '/'}
                        className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
                    >
                        <span className="icon">{icon}</span>
                        {label}
                    </NavLink>
                ))}
            </nav>

            <div style={{ padding: '16px', borderTop: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: 'var(--bg-primary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                    <Activity size={14} style={{ color: 'var(--accent-green)' }} />
                    <span style={{ fontSize: '0.775rem', color: 'var(--text-secondary)' }}>v1.0.0 · 研究原型</span>
                </div>
            </div>
        </aside>
    );
}
