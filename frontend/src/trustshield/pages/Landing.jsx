import { Link } from 'react-router-dom';
import { Shield, Link2, Mail, MessageSquare, QrCode, ArrowRight, ChevronRight } from 'lucide-react';

const SCANNERS = [
  { to: '/scan/url', icon: Link2, title: 'URL Scanner', desc: 'Inspect links for phishing & typosquatting.' },
  { to: '/scan/email', icon: Mail, title: 'Email Scanner', desc: 'Spot phishing emails and malicious links.' },
  { to: '/scan/message', icon: MessageSquare, title: 'Message Scanner', desc: 'Detect SMS & chat scams instantly.' },
  { to: '/scan/qr', icon: QrCode, title: 'QR Scanner', desc: 'Decode & analyze QR destinations safely.' },
];

const CHAIN = ['Scam Message', 'Fake Website', 'Credential Theft', 'OTP Theft', 'Financial Fraud'];

export default function Landing() {
  return (
    <div className="ts-shell" style={{ display: 'block' }}>
      <div className="ts-bg-grid" />
      <div style={{ position: 'relative', zIndex: 1, maxWidth: 1080, margin: '0 auto', padding: '30px clamp(18px,5vw,40px) 70px' }}>
        {/* Nav */}
        <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 60 }}>
          <div className="ts-brand" style={{ padding: 0 }}>
            <Shield size={26} color="#22d3ee" />
            <span className="ts-brand-name">Trust<span>Shield</span></span>
          </div>
          <Link to="/dashboard" className="ts-btn ts-btn-ghost" data-testid="landing-dashboard-btn" style={{ padding: '9px 16px' }}>
            Open Dashboard <ChevronRight size={16} />
          </Link>
        </header>

        {/* Hero */}
        <section className="ts-fade-in" style={{ textAlign: 'center', maxWidth: 760, margin: '0 auto 54px' }}>
          <div className="ts-chip" style={{ color: '#a3e635', borderColor: 'rgba(163,230,53,0.35)', marginBottom: 20 }}>
            <Shield size={14} /> AI-powered digital trust
          </div>
          <h1 style={{ fontSize: 'clamp(34px, 6vw, 58px)', lineHeight: 1.05, margin: 0, fontWeight: 800, letterSpacing: '-0.03em' }}>
            Can you trust this<br /><span style={{ color: '#22d3ee' }}>digital interaction?</span>
          </h1>
          <p style={{ fontSize: 18, color: 'var(--ts-muted)', margin: '22px auto 30px', maxWidth: 600, lineHeight: 1.6 }}>
            TrustShield analyzes URLs, emails, messages and QR codes for phishing and scams —
            giving you a clear risk score, the evidence behind it, and what to do next.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Link to="/scan/message" className="ts-btn ts-btn-primary" data-testid="landing-start-btn">
              Start Scanning <ArrowRight size={18} />
            </Link>
            <Link to="/scan/url" className="ts-btn ts-btn-ghost" data-testid="landing-url-btn">Check a URL</Link>
          </div>
        </section>

        {/* Scanner cards */}
        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px,1fr))', gap: 15, marginBottom: 56 }}>
          {SCANNERS.map(({ to, icon: Icon, title, desc }) => (
            <Link key={to} to={to} className="ts-card ts-card-pad" data-testid={`landing-card-${to.split('/').pop()}`}
              style={{ textDecoration: 'none', color: 'inherit', transition: 'transform .18s ease, border-color .18s ease' }}
              onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-4px)'; e.currentTarget.style.borderColor = 'rgba(34,211,238,0.4)'; }}
              onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.borderColor = ''; }}>
              <span style={{ display: 'grid', placeItems: 'center', width: 44, height: 44, borderRadius: 12,
                background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.25)' }}><Icon size={22} color="#22d3ee" /></span>
              <h3 style={{ margin: '16px 0 6px', fontSize: 17 }}>{title}</h3>
              <p style={{ margin: 0, color: 'var(--ts-muted)', fontSize: 14, lineHeight: 1.5 }}>{desc}</p>
            </Link>
          ))}
        </section>

        {/* Attack chain */}
        <section className="ts-card ts-card-pad" style={{ padding: '28px 24px' }}>
          <h2 style={{ margin: '0 0 6px', fontSize: 20 }}>How a scam unfolds</h2>
          <p style={{ margin: '0 0 22px', color: 'var(--ts-muted)', fontSize: 14.5 }}>
            TrustShield breaks the chain early — at the message or link — before it reaches financial fraud.
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }} data-testid="attack-chain">
            {CHAIN.map((step, i) => (
              <div key={step} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ padding: '9px 15px', borderRadius: 10, fontSize: 13.5, fontWeight: 600, whiteSpace: 'nowrap',
                  background: i === 0 ? 'rgba(34,211,238,0.14)' : 'rgba(248,113,113,0.10)',
                  border: `1px solid ${i === 0 ? 'rgba(34,211,238,0.4)' : 'rgba(248,113,113,0.3)'}`,
                  color: i === 0 ? '#22d3ee' : '#fca5a5' }}>{step}</span>
                {i < CHAIN.length - 1 && <ArrowRight size={16} color="var(--ts-muted)" />}
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
