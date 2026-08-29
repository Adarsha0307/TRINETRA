import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Landing from './pages/Landing';
import Dashboard from './pages/Dashboard';
import UrlScanner from './pages/UrlScanner';
import EmailScanner from './pages/EmailScanner';
import MessageScanner from './pages/MessageScanner';
import QrScanner from './pages/QrScanner';
import History from './pages/History';
import ScanDetail from './pages/ScanDetail';
import About from './pages/About';

export default function TrustShieldRouter() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route element={<Layout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan/url" element={<UrlScanner />} />
        <Route path="/scan/email" element={<EmailScanner />} />
        <Route path="/scan/message" element={<MessageScanner />} />
        <Route path="/scan/qr" element={<QrScanner />} />
        <Route path="/history" element={<History />} />
        <Route path="/history/:id" element={<ScanDetail />} />
        <Route path="/about" element={<About />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
