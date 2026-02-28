import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getScan, cancelScan, downloadPdf } from '../api';
import {
    ArrowLeft, Download, StopCircle, AlertTriangle, ShieldCheck,
    ChevronDown, ChevronUp, RefreshCw, FileText
} from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const SEV_COLORS = { High: '#ef4444', Medium: '#f59e0b', Low: '#3b82f6' };

function VulnCard({ vuln }) {
    const [open, setOpen] = useState(false);

    const badgeClass = vuln.severity === 'High' ? 'badge-high'
        : vuln.severity === 'Medium' ? 'badge-medium' : 'badge-low';

    return (
        <div style={{
            background: 'var(--bg-primary)',
            border: `1px solid ${open ? 'var(--accent-blue)' : 'var(--border-subtle)'}`,
            borderRadius: 'var(--radius-md)',
            overflow: 'hidden',
            transition: 'var(--transition)',
        }}>
            <button
                onClick={() => setOpen(!open)}
                style={{
                    width: '100%', background: 'none', border: 'none', cursor: 'pointer',
                    padding: '14px 16px',
                    display: 'flex', alignItems: 'center', gap: 12,
                    textAlign: 'left',
                }}
            >
                <span className={`badge ${badgeClass}`}>{vuln.severity}</span>
                <span style={{ flex: 1, fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.875rem' }}>
                    {vuln.vuln_type}
                </span>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.775rem', color: 'var(--text-muted)', marginRight: 8 }}>
                    {vuln.endpoint}
                </span>
                {open ? <ChevronUp size={14} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                    : <ChevronDown size={14} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />}
            </button>
            {open && (
                <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--border-subtle)' }}>
                    <div style={{ paddingTop: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
                        <div>
                            <div className="form-label" style={{ marginBottom: 4 }}>Description</div>
                            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{vuln.description}</p>
                        </div>
                        <div>
                            <div className="form-label" style={{ marginBottom: 4 }}>Evidence</div>
                            <div className="code-block">{vuln.evidence}</div>
                        </div>
                        <div>
                            <div className="form-label" style={{ marginBottom: 4 }}>Endpoint</div>
                            <div className="code-block">{vuln.endpoint}</div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default function ScanDetail() {
    const { scanId } = useParams();
    const navigate = useNavigate();
    const [scan, setScan] = useState(null);
    const [loading, setLoading] = useState(true);
    const [downloading, setDownloading] = useState(false);
    const [filter, setFilter] = useState('All');

    const fetchScan = useCallback(async () => {
        try {
            const data = await getScan(scanId);
            setScan(data);
        } catch (e) { console.error(e); }
        setLoading(false);
    }, [scanId]);

    useEffect(() => {
        fetchScan();
    }, [fetchScan]);

    // Live polling when running
    useEffect(() => {
        if (!scan || scan.status !== 'running') return;
        const interval = setInterval(fetchScan, 3000);
        return () => clearInterval(interval);
    }, [scan, fetchScan]);

    const handleCancel = async () => {
        await cancelScan(scanId);
        fetchScan();
    };

    const handleDownload = async () => {
        setDownloading(true);
        try { await downloadPdf(scanId); }
        catch (e) { alert('PDF generation failed: ' + e.message); }
        setDownloading(false);
    };

    if (loading) {
        return (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', color: 'var(--text-muted)' }}>
                Loading...
            </div>
        );
    }

    if (!scan) {
        return (
            <div style={{ padding: 40 }}>
                <button className="btn btn-ghost" onClick={() => navigate('/scans')}><ArrowLeft size={14} /> Back</button>
                <p style={{ marginTop: 20, color: 'var(--text-muted)' }}>Scan not found.</p>
            </div>
        );
    }

    const vulns = scan.vulnerabilities || [];
    const filteredVulns = filter === 'All' ? vulns : vulns.filter(v => v.severity === filter);

    // Pie data
    const pieData = Object.entries(scan.summary_counts || {})
        .filter(([_, v]) => v > 0)
        .map(([name, value]) => ({ name, value }));

    return (
        <>
            <div className="main-header">
                <button className="btn btn-ghost btn-sm" style={{ marginBottom: 12 }} onClick={() => navigate('/scans')}>
                    <ArrowLeft size={14} /> Back to Scans
                </button>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <div>
                        <h1 className="page-title">Scan #{scan.id}</h1>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 6 }}>
                            <span className={`status-dot ${scan.status}`} />
                            <span className={`badge badge-${scan.status === 'completed' ? 'success' : scan.status}`}>
                                {scan.status}
                            </span>
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                                {new Date(scan.created_at).toLocaleString()}
                            </span>
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                        <button className="btn btn-ghost btn-sm" onClick={fetchScan}><RefreshCw size={14} /></button>
                        {scan.status === 'completed' && (
                            <button className="btn btn-primary btn-sm" onClick={handleDownload} disabled={downloading}>
                                {downloading ? 'Generating...' : <><Download size={14} /> PDF Report</>}
                            </button>
                        )}
                        {(scan.status === 'running' || scan.status === 'queued') && (
                            <button className="btn btn-danger btn-sm" onClick={handleCancel}>
                                <StopCircle size={14} /> Cancel
                            </button>
                        )}
                    </div>
                </div>
            </div>

            <div className="content-area">
                {scan.status === 'running' && (
                    <div className="card" style={{ marginBottom: 20, borderColor: 'var(--accent-blue)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                            <span className="status-dot running" />
                            <span style={{ fontWeight: 600 }}>Scan in progress...</span>
                            <div className="progress-bar" style={{ flex: 1 }}>
                                <div className="progress-fill" />
                            </div>
                        </div>
                    </div>
                )}

                {/* Summary cards */}
                <div className="stat-grid" style={{ marginBottom: 24 }}>
                    <div className="stat-card">
                        <div className="stat-card-value">{vulns.length}</div>
                        <div className="stat-card-label">Total Findings</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-card-value" style={{ color: 'var(--sev-high)' }}>{scan.summary_counts?.High ?? 0}</div>
                        <div className="stat-card-label">High Severity</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-card-value" style={{ color: 'var(--sev-medium)' }}>{scan.summary_counts?.Medium ?? 0}</div>
                        <div className="stat-card-label">Medium Severity</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-card-value" style={{ color: 'var(--sev-low)' }}>{scan.summary_counts?.Low ?? 0}</div>
                        <div className="stat-card-label">Low Severity</div>
                    </div>
                </div>

                <div className="grid-2" style={{ marginBottom: 24 }}>
                    {/* Pie chart */}
                    {pieData.length > 0 && (
                        <div className="card">
                            <div className="card-header">
                                <span className="card-title">Severity Breakdown</span>
                            </div>
                            <div className="chart-container">
                                <ResponsiveContainer width="100%" height="100%">
                                    <PieChart>
                                        <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} dataKey="value" strokeWidth={0}>
                                            {pieData.map((entry, i) => (
                                                <Cell key={i} fill={SEV_COLORS[entry.name] || '#3b82f6'} />
                                            ))}
                                        </Pie>
                                        <Tooltip
                                            contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)', fontSize: 12 }}
                                        />
                                        <Legend iconType="circle" iconSize={10} wrapperStyle={{ fontSize: 12, color: 'var(--text-secondary)' }} />
                                    </PieChart>
                                </ResponsiveContainer>
                            </div>
                        </div>
                    )}

                    {/* Scan info */}
                    <div className="card">
                        <div className="card-header">
                            <span className="card-title">Scan Info</span>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                            {[
                                ['Scan ID', `#${scan.id}`],
                                ['Status', scan.status],
                                ['Type', scan.scan_type],
                                ['Created', new Date(scan.created_at).toLocaleString()],
                                ['Error', scan.error_message || 'None'],
                            ].map(([k, v]) => (
                                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>{k}</span>
                                    <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontFamily: k === 'Scan ID' ? 'JetBrains Mono, monospace' : undefined }}>{v}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Vulnerabilities */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Findings ({filteredVulns.length})</span>
                        <div style={{ display: 'flex', gap: 6 }}>
                            {['All', 'High', 'Medium', 'Low'].map(sev => (
                                <button
                                    key={sev}
                                    className={`btn btn-sm ${filter === sev ? 'btn-primary' : 'btn-ghost'}`}
                                    onClick={() => setFilter(sev)}
                                >
                                    {sev}
                                </button>
                            ))}
                        </div>
                    </div>

                    {filteredVulns.length === 0 ? (
                        <div className="empty-state" style={{ padding: '40px 20px' }}>
                            <div className="empty-state-icon">
                                {vulns.length === 0 ? <ShieldCheck size={40} /> : <AlertTriangle size={40} />}
                            </div>
                            <h3>{vulns.length === 0 ? 'No vulnerabilities found' : `No ${filter} findings`}</h3>
                            <p>{vulns.length === 0 ? 'Great! The API passed all security checks.' : `There are no ${filter.toLowerCase()} severity findings.`}</p>
                        </div>
                    ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                            {filteredVulns.map((v, i) => (
                                <VulnCard key={i} vuln={v} />
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </>
    );
}
