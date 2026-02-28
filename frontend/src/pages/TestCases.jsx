import React, { useState } from 'react';
import { FlaskConical, Copy, CheckCheck, Terminal, Shield, AlertTriangle, Server } from 'lucide-react';

const BASE = 'http://localhost:9002';

const TOKEN_ALICE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InVzZXIifQ.bESAtRbJA_1EWKHav0odPcSbOyHNRzraTtWhN0SbbCc';

const TEST_CASES = [
    {
        category: '正常功能',
        icon: <Server size={16} />,
        color: 'var(--accent-green)',
        bg: 'rgba(16,185,129,0.1)',
        items: [
            {
                id: 'TC-01',
                name: '登入取得 Token（alice）',
                desc: '以普通用戶 alice 身份登入，取得 JWT Token。不需要密碼（demo 漏洞）。',
                method: 'POST',
                url: `${BASE}/login?username=alice`,
                cmd: `curl -X POST "${BASE}/login?username=alice"`,
                expected: '200 - 回傳 access_token',
                owasp: null,
            },
            {
                id: 'TC-02',
                name: '登入取得 Token（admin）',
                desc: '以管理員身份登入，取得高權限 JWT Token。',
                method: 'POST',
                url: `${BASE}/login?username=admin`,
                cmd: `curl -X POST "${BASE}/login?username=admin"`,
                expected: '200 - 回傳 admin access_token',
                owasp: null,
            },
            {
                id: 'TC-03',
                name: '查看 API 說明文件',
                desc: '查看 demo_api 的 OpenAPI 互動式說明文件。',
                method: 'GET',
                url: `${BASE}/docs`,
                cmd: `curl "${BASE}/docs"`,
                expected: '200 - HTML 說明文件頁面',
                owasp: null,
            },
        ]
    },
    {
        category: 'BOLA（API1）- 物件層級授權破壞',
        icon: <AlertTriangle size={16} />,
        color: 'var(--sev-high)',
        bg: 'rgba(239,68,68,0.1)',
        items: [
            {
                id: 'TC-04',
                name: '越權查看他人帳戶',
                desc: 'alice (user_id=1) 嘗試存取 bob (owner_id=2) 的帳戶 1002，應回傳 403 但實際回傳 200（BOLA 漏洞）。',
                method: 'GET',
                url: `${BASE}/accounts/1002`,
                cmd: `curl -H "Authorization: Bearer ${TOKEN_ALICE}" "${BASE}/accounts/1002"`,
                expected: '❌ 應 403，實際 200（漏洞！）',
                owasp: 'API1:2023',
            },
            {
                id: 'TC-05',
                name: '越權查看他人交易',
                desc: 'alice 嘗試查看屬於 bob 的交易記錄 5002。',
                method: 'GET',
                url: `${BASE}/transactions/5002`,
                cmd: `curl -H "Authorization: Bearer ${TOKEN_ALICE}" "${BASE}/transactions/5002"`,
                expected: '❌ 應 403，實際 200（漏洞！）',
                owasp: 'API1:2023',
            },
        ]
    },
    {
        category: 'BFLA（API5）- 功能層級授權破壞',
        icon: <AlertTriangle size={16} />,
        color: 'var(--sev-high)',
        bg: 'rgba(239,68,68,0.1)',
        items: [
            {
                id: 'TC-06',
                name: '普通用戶存取管理員清單',
                desc: 'alice 以一般用戶身份呼叫 /admin/users，應被拒絕但實際成功（BFLA 漏洞）。',
                method: 'GET',
                url: `${BASE}/admin/users`,
                cmd: `curl -H "Authorization: Bearer ${TOKEN_ALICE}" "${BASE}/admin/users"`,
                expected: '❌ 應 403，實際 200（漏洞！）',
                owasp: 'API5:2023',
            },
            {
                id: 'TC-07',
                name: '普通用戶執行權限提升',
                desc: 'alice 嘗試把 user_id=2 提升為 admin，應被拒絕但實際成功。',
                method: 'POST',
                url: `${BASE}/admin/promote`,
                cmd: `curl -X POST -H "Authorization: Bearer ${TOKEN_ALICE}" -H "Content-Type: application/json" -d '{"user_id": 2}' "${BASE}/admin/promote"`,
                expected: '❌ 應 403，實際 200（漏洞！）',
                owasp: 'API5:2023',
            },
        ]
    },
    {
        category: '驗證相關（API2）',
        icon: <Shield size={16} />,
        color: 'var(--sev-medium)',
        bg: 'rgba(245,158,11,0.1)',
        items: [
            {
                id: 'TC-08',
                name: '無 Token 存取受保護端點',
                desc: '不帶 Authorization Header 直接存取需要驗證的端點。',
                method: 'GET',
                url: `${BASE}/accounts/1001`,
                cmd: `curl "${BASE}/accounts/1001"`,
                expected: '✅ 401 Unauthorized',
                owasp: 'API2:2023',
            },
            {
                id: 'TC-09',
                name: '使用錯誤密碼（demo）',
                desc: '嘗試用不存在的用戶登入。',
                method: 'POST',
                url: `${BASE}/login?username=hacker`,
                cmd: `curl -X POST "${BASE}/login?username=hacker"`,
                expected: '✅ 404 User not found',
                owasp: 'API2:2023',
            },
        ]
    },
    {
        category: '庫存管理（API9）- 暴露文件',
        icon: <Server size={16} />,
        color: 'var(--accent-blue)',
        bg: 'rgba(59,130,246,0.1)',
        items: [
            {
                id: 'TC-10',
                name: '查看 OpenAPI JSON Schema',
                desc: 'demo_api 暴露完整的 OpenAPI JSON 規格，攻擊者可以用來了解所有端點。',
                method: 'GET',
                url: `${BASE}/openapi.json`,
                cmd: `curl "${BASE}/openapi.json" | python3 -m json.tool`,
                expected: '⚠️ 200 - 完整 API 規格（資訊洩漏）',
                owasp: 'API9:2023',
            },
        ]
    },
];

const methodColor = {
    GET: 'var(--accent-green)',
    POST: 'var(--accent-blue)',
    PATCH: 'var(--accent-yellow)',
    DELETE: 'var(--sev-high)',
};

function CopyButton({ text }) {
    const [copied, setCopied] = useState(false);
    const handleCopy = () => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };
    return (
        <button onClick={handleCopy} className="btn btn-ghost btn-sm" style={{ flexShrink: 0 }} title="複製指令">
            {copied ? <CheckCheck size={13} style={{ color: 'var(--accent-green)' }} /> : <Copy size={13} />}
        </button>
    );
}

export default function TestCases() {
    const [openId, setOpenId] = useState(null);

    return (
        <>
            <div className="main-header">
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <div>
                        <h1 className="page-title">測試項目清單</h1>
                        <p className="page-subtitle">針對 Demo API 的手動測試指令，涵蓋 OWASP API Top 10</p>
                    </div>
                    <div style={{
                        display: 'flex', alignItems: 'center', gap: 8,
                        background: 'var(--bg-card)', border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-sm)', padding: '8px 16px'
                    }}>
                        <Terminal size={14} style={{ color: 'var(--accent-cyan)' }} />
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem', color: 'var(--accent-cyan)' }}>
                            API: {BASE}
                        </span>
                    </div>
                </div>
            </div>

            <div className="content-area">
                {/* Token helper card */}
                <div className="card" style={{ marginBottom: 20, borderColor: 'rgba(59,130,246,0.4)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                        <Shield size={16} style={{ color: 'var(--accent-blue)' }} />
                        <span className="card-title">測試用 Token（永久有效）</span>
                    </div>
                    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                        {[
                            { label: 'alice（普通用戶）', cmd: `curl -X POST "${BASE}/login?username=alice"` },
                            { label: 'bob（普通用戶）', cmd: `curl -X POST "${BASE}/login?username=bob"` },
                            { label: 'admin（管理員）', cmd: `curl -X POST "${BASE}/login?username=admin"` },
                        ].map(({ label, cmd }) => (
                            <div key={label} style={{ flex: 1, minWidth: 220, background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '10px 12px' }}>
                                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 6 }}>{label}</div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                    <code style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono, monospace', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cmd}</code>
                                    <CopyButton text={cmd} />
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Test categories */}
                {TEST_CASES.map(category => (
                    <div key={category.category} style={{ marginBottom: 24 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                            <div style={{ width: 28, height: 28, borderRadius: 6, background: category.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', color: category.color }}>
                                {category.icon}
                            </div>
                            <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-heading)' }}>{category.category}</h2>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                            {category.items.map(tc => (
                                <div
                                    key={tc.id}
                                    style={{
                                        background: 'var(--bg-card)',
                                        border: `1px solid ${openId === tc.id ? 'var(--accent-blue)' : 'var(--border)'}`,
                                        borderRadius: 'var(--radius-md)',
                                        overflow: 'hidden',
                                        transition: 'var(--transition)',
                                    }}
                                >
                                    {/* Header row */}
                                    <div
                                        onClick={() => setOpenId(openId === tc.id ? null : tc.id)}
                                        style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 16px', cursor: 'pointer' }}
                                    >
                                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', color: 'var(--text-muted)', flexShrink: 0, width: 52 }}>{tc.id}</span>
                                        <span style={{
                                            fontFamily: 'JetBrains Mono, monospace',
                                            fontSize: '0.72rem', fontWeight: 700,
                                            color: methodColor[tc.method] || 'var(--text-muted)',
                                            padding: '2px 6px',
                                            background: 'var(--bg-primary)',
                                            borderRadius: 4,
                                            flexShrink: 0,
                                            width: 48,
                                            textAlign: 'center',
                                        }}>{tc.method}</span>
                                        <span style={{ flex: 1, fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>{tc.name}</span>
                                        {tc.owasp && (
                                            <span className="badge badge-high" style={{ flexShrink: 0 }}>{tc.owasp}</span>
                                        )}
                                        <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{openId === tc.id ? '▲' : '▼'}</span>
                                    </div>

                                    {/* Expanded */}
                                    {openId === tc.id && (
                                        <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--border-subtle)' }}>
                                            <div style={{ paddingTop: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
                                                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{tc.desc}</p>

                                                <div>
                                                    <div className="form-label" style={{ marginBottom: 6 }}>端點</div>
                                                    <div className="code-block">{tc.url}</div>
                                                </div>

                                                <div>
                                                    <div className="form-label" style={{ marginBottom: 6 }}>curl 指令</div>
                                                    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                                                        <div className="code-block" style={{ flex: 1, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{tc.cmd}</div>
                                                        <CopyButton text={tc.cmd} />
                                                    </div>
                                                </div>

                                                <div>
                                                    <div className="form-label" style={{ marginBottom: 6 }}>預期結果</div>
                                                    <div style={{
                                                        fontSize: '0.85rem',
                                                        padding: '8px 12px',
                                                        background: 'var(--bg-primary)',
                                                        border: '1px solid var(--border)',
                                                        borderRadius: 'var(--radius-sm)',
                                                        color: tc.expected.includes('❌') ? 'var(--sev-high)' : tc.expected.includes('⚠️') ? 'var(--sev-medium)' : 'var(--accent-green)'
                                                    }}>
                                                        {tc.expected}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </>
    );
}
