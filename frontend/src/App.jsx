import './trustshield/trustshield.css';
import TrustShieldRouter from './trustshield/TrustShieldRouter';

// Authentication is intentionally out of scope for the MVP — users access the
// scanners and dashboard directly (see PART 1/2 handoff docs).
export default function App() {
  return <TrustShieldRouter />;
}
