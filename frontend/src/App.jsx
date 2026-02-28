import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Projects from './pages/Projects';
import Scans from './pages/Scans';
import ScanDetail from './pages/ScanDetail';
import Reports from './pages/Reports';
import TestCases from './pages/TestCases';
import AuthMatrix from './pages/AuthMatrix';
import './index.css';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <div className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:scanId" element={<ScanDetail />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/testcases" element={<TestCases />} />
            <Route path="/auth-matrix" element={<AuthMatrix />} />
          </Routes>
        </div>
      </div>
    </BrowserRouter>
  );
}
