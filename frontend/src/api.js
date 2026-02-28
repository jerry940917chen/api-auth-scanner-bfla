import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:9000',
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
});

// Projects
export const getProjects = () => api.get('/projects').then(r => r.data);
export const createProject = (data) => api.post('/projects', data).then(r => r.data);
export const deleteProject = (id) => api.delete(`/projects/${id}`);

// Scans
export const startScan = (projectId, payload) =>
  api.post(`/projects/${projectId}/scans`, payload).then(r => r.data);

export const getScan = (scanId) => api.get(`/scans/${scanId}`).then(r => r.data);

export const cancelScan = (scanId) =>
  api.post(`/scans/${scanId}/cancel`).then(r => r.data);

export const getAuthMatrix = (scanId) =>
  api.get(`/scans/${scanId}/auth-matrix`).then(r => r.data);

export const getScanReport = (scanId) =>
  api.get(`/scans/${scanId}/report.json`).then(r => r.data);

export const downloadPdf = async (scanId) => {
  const response = await api.get(`/scans/${scanId}/report.pdf`, {
    responseType: 'blob',
    timeout: 300000 // 5 minutes for AI generation
  });
  const url = URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `audit_report_${scanId}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
};

export const healthCheck = () => api.get('/health').then(r => r.data);

export default api;
