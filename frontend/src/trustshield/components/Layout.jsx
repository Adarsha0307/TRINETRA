import { NavLink, Outlet, Link } from 'react-router-dom';
import { Shield, LayoutDashboard, Link2, Mail, MessageSquare, QrCode, History } from 'lucide-react';

const NAV = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, testid: 'nav-dashboard' },
  { to: '/scan/url', label: 'URL Scanner', icon: Link2, testid: 'nav-url' },
  { to: '/scan/email', label: 'Email Scanner', icon: Mail, testid: 'nav-email' },
  { to: '/scan/message', label: 'Message Scanner', icon: MessageSquare, testid: 'nav-message' },
  { to: '/scan/qr', label: 'QR Scanner', icon: QrCode, testid: 'nav-qr' },
  { to: '/history', label: 'Scan History', icon: History, testid: 'nav-history' },
];

export default function Layout() {
  return (
    <div className="ts-shell">
      <div className="ts-bg-grid" />
      <aside className="ts-sidebar" data-testid="sidebar">
        <Link to="/" className="ts-brand" data-testid="brand-link">
          <Shield size={26} color="#22d3ee" />
          <span className="ts-brand-name">Trust<span>Shield</span></span>
        </Link>
        <div className="ts-nav-section">Scanners &amp; Data</div>
        {NAV.map(({ to, label, icon: Icon, testid }) => (
          <NavLink key={to} to={to} data-testid={testid}
            className={({ isActive }) => 'ts-navlink' + (isActive ? ' active' : '')}>
            <Icon size={18} /> {label}
          </NavLink>
        ))}
        <div style={{ marginTop: 'auto', paddingTop: 18 }}>
          <NavLink to="/about" data-testid="nav-about"
            className={({ isActive }) => 'ts-navlink' + (isActive ? ' active' : '')}>
            <Shield size={18} /> About
          </NavLink>
        </div>
      </aside>

      <div className="ts-main">
        <header className="ts-topbar">
          <Link to="/" className="ts-brand" style={{ padding: 0 }}>
            <Shield size={22} color="#22d3ee" />
            <span className="ts-brand-name" style={{ fontSize: 17 }}>Trust<span>Shield</span></span>
          </Link>
        </header>
        <div className="ts-content">
          <Outlet />
        </div>
      </div>

      <nav className="ts-mobile-nav" data-testid="mobile-nav">
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} className={({ isActive }) => (isActive ? 'active' : '')}>
            <Icon size={20} /> {label.split(' ')[0]}
          </NavLink>
        ))}
      </nav>
    </div>
  );
}
