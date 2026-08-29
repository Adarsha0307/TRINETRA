import { useState } from 'react';
import { QrCode, Upload, ShieldCheck } from 'lucide-react';
import { apiPostForm } from '../lib/api';
import RiskResult from '../components/RiskResult';
import { Loader, ErrorBanner, PageHeader } from '../components/ui';

export default function QrScanner() {
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  function onFile(e) {
    const f = e.target.files?.[0];
    setResult(null); setError('');
    if (!f) return;
    if (!f.type.startsWith('image/')) { setError('Please upload an image file (PNG/JPG).'); return; }
    if (f.size > 2 * 1024 * 1024) { setError('Image is too large (max 2MB).'); return; }
    setFile(f);
    setPreview(URL.createObjectURL(f));
  }

  async function submit(e) {
    e.preventDefault();
    setError(''); setResult(null);
    if (!file) { setError('Please choose a QR code image to scan.'); return; }
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append('image', file);
      setResult(await apiPostForm('/scan/qr', fd));
    } catch (err) {
      setError(err.message || 'Unable to scan this QR image.');
    } finally { setLoading(false); }
  }

  return (
    <div>
      <PageHeader icon={QrCode} title="QR Code Scanner"
        subtitle="Upload a QR code image. TrustShield decodes the destination and analyzes it — it never opens the link automatically." />
      <form onSubmit={submit} className="ts-card ts-card-pad" data-testid="qr-form">
        <label className="ts-label">QR code image (max 2MB)</label>
        <label htmlFor="qr-file" data-testid="qr-dropzone"
          style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, padding: 28,
            border: '1.5px dashed var(--ts-border-strong)', borderRadius: 14, cursor: 'pointer',
            background: 'rgba(4,10,20,0.4)' }}>
          {preview
            ? <img src={preview} alt="QR preview" style={{ width: 150, height: 150, objectFit: 'contain', borderRadius: 10 }} />
            : <Upload size={30} color="#22d3ee" />}
          <span style={{ color: 'var(--ts-muted)', fontSize: 14 }}>{file ? file.name : 'Click to upload a QR code image'}</span>
          <input id="qr-file" data-testid="qr-file" type="file" accept="image/*" onChange={onFile} style={{ display: 'none' }} />
        </label>
        <button type="submit" className="ts-btn ts-btn-primary" data-testid="qr-submit"
          disabled={loading} style={{ marginTop: 16 }}>
          <ShieldCheck size={18} /> {loading ? 'Decoding…' : 'Scan QR Code'}
        </button>
      </form>
      <div style={{ marginTop: 18, display: 'grid', gap: 14 }}>
        <ErrorBanner message={error} />
        {loading && <Loader label="Decoding QR code…" />}
        {!loading && result && <RiskResult result={result} decodedDestination={result.decodedDestination} />}
      </div>
    </div>
  );
}
