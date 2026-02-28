import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getScan, downloadPdf } from '../api';
import { FileText, Download, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function Reports() {
    const navigate = useNavigate();
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [downloading, setDownloading] = useState(null);

    useEffect(() => {
        const stored = JSON.parse(localStorage.getItem('scanIds') || '[]');
        Promise.allSettled(stored.map(id => getScan(id))).then(results => {
            const completed = results
                .filter(r => r.status === 'fulfilled' && r.value.status === 'completed')
                .map(r => r.value);
            setScans(completed.reverse());
            setLoading(false);
        });
    }, []);

    const handleDownload = async (scanId) => {
        setDownloading(scanId);
        try { await downloadPdf(scanId); }
        catch (e) { alert('PDF failed: ' + e.message); }
        setDownloading(null);
    };

    const totalVulns = scans.reduce((acc, s) => acc + (s.vulnerabilities?.length || 0), 0);
    const highCount = scans.reduce((acc, s) => acc + (s.summary_counts?.High || 0), 0);

    return (
        <>
            <div className="main-header">
                <h1 className="page-title">Reports</h1>
                <p className="page-subtitle">Download PDF audit reports for completed scans</p>
            </div>
            <div className="content-area">
                {/* Summary */}
                <div className="stat-grid" style={{ marginBottom: 24 }}>
                    <div className="stat-card">
                        <div className="stat-card-value">{scans.length}</div>
                        <div className="stat-card-label">Completed Scans</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-card-value" style={{ color: 'var(--sev-high)' }}>{highCount}</div>
                        <div className="stat-card-label">Total High Severity</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-card-value">{totalVulns}</div>
                        <div className="stat-card-label">Total Findings</div>
                    </div>
                </div>

                {loading ? (
                    <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>Loading...</div>
                ) : scans.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state-icon"><FileText size={48} /></div>
                        <h3>No reports available</h3>
                        <p>Complete a scan to generate a downloadable PDF audit report.</p>
                    </div>
                ) : (
                    <div className="card" style={{ padding: 0 }}>
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Scan ID</th>
                                    <th>Date</th>
                                    <th>Total Findings</th>
                                    <th>Risk Level</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {scans.map(s => {
                                    const high = s.summary_counts?.High || 0;
                                    const risk = high > 0 ? 'Critical' : (s.summary_counts?.Medium || 0) > 0 ? 'Medium' : 'Low';
                                    const riskClass = high > 0 ? 'badge-high' : risk === 'Medium' ? 'badge-medium' : 'badge-success';
                                    return (
                                        <tr key={s.id}>
                                            <td>
                                                <span
                                                    style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 600, color: 'var(--accent-blue)', cursor: 'pointer' }}
                                                    onClick={() => navigate(`/scans/${s.id}`)}
                                                >
                                                    #{s.id}
                                                </span>
                                            </td>
                                            <td style={{ fontSize: '0.8rem' }}>{new Date(s.created_at).toLocaleString()}</td>
                                            <td>
                                                <div style={{ display: 'flex', gap: 6 }}>
                                                    {high > 0 && <span className="badge badge-high">H:{high}</span>}
                                                    {(s.summary_counts?.Medium || 0) > 0 && <span className="badge badge-medium">M:{s.summary_counts.Medium}</span>}
                                                    {(s.summary_counts?.Low || 0) > 0 && <span className="badge badge-low">L:{s.summary_counts.Low}</span>}
                                                </div>
                                            </td>
                                            <td><span className={`badge ${riskClass}`}>{risk}</span></td>
                                            <td>
                                                <button
                                                    className="btn btn-ghost btn-sm"
                                                    onClick={() => handleDownload(s.id)}
                                                    disabled={downloading === s.id}
                                                >
                                                    <Download size={12} />
                                                    {downloading === s.id ? 'Generating...' : 'PDF'}
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </>
    );
}
