import { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:5000/api';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

type OracleEntry = { message: string; tag: string };
type Tab = 'euf-cma' | 'length-ext' | 'compare';

const PA5Demo = () => {
  const [activeTab, setActiveTab] = useState<Tab>('euf-cma');

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      {/* Header */}
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-1">PA#5: Message Authentication Codes</h2>
        <p className="text-sm text-gray-500">
          Explore EUF-CMA security, attempt forgeries, and witness the length-extension
          vulnerability that motivates HMAC.
        </p>
      </div>

      {/* Tab Bar */}
      <div className="flex space-x-1 bg-gray-100 rounded-lg p-1">
        {([
          ['euf-cma',    'EUF-CMA Forgery Game'],
          ['length-ext', 'Length-Extension Attack'],
          ['compare',    'PRF-MAC vs CBC-MAC'],
        ] as [Tab, string][]).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`flex-1 py-2 px-3 text-sm font-semibold rounded-md transition-colors ${
              activeTab === key
                ? 'bg-white shadow text-indigo-700'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'euf-cma'    && <EufCmaGame />}
      {activeTab === 'length-ext' && <LengthExtensionDemo />}
      {activeTab === 'compare'    && <MacCompareDemo />}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Tab 1 – EUF-CMA Forgery Game
// ─────────────────────────────────────────────────────────────────────────────

const EufCmaGame = () => {
  const [queryMessage, setQueryMessage]     = useState('');
  const [forgeMessage, setForgeMessage]     = useState('');
  const [forgeTag,     setForgeTag]         = useState('');
  const [history,      setHistory]          = useState<OracleEntry[]>([]);
  const [lastResult,   setLastResult]       = useState<{ accepted: boolean; correctTag?: string } | null>(null);
  const [forgeAttempts, setForgeAttempts]   = useState(0);
  const [forgeSuccesses, setForgeSuccesses] = useState(0);
  const [error,        setError]            = useState('');
  const [loading,      setLoading]          = useState(false);

  const fetchHistory = async () => {
    try {
      const res  = await fetch(`${API_BASE}/pa5/history`);
      const data = await res.json();
      if (data.status === 'success') setHistory(data.history);
    } catch (_) {}
  };

  useEffect(() => { fetchHistory(); }, []);

  const queryOracle = async () => {
    if (!queryMessage.trim()) return;
    setError(''); setLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/pa5/oracle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: queryMessage }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setHistory(prev => [...prev, { message: data.message, tag: data.tag }]);
        setQueryMessage('');
      } else {
        setError(data.message);
      }
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  const submitForgery = async () => {
    if (!forgeMessage.trim() || !forgeTag.trim()) return;
    setError(''); setLastResult(null); setLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/pa5/forge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: forgeMessage, tag: forgeTag }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        const accepted = data.accepted as boolean;
        setForgeAttempts(p => p + 1);
        if (accepted) setForgeSuccesses(p => p + 1);
        setLastResult({ accepted, correctTag: data.correct_tag });
      } else {
        setError(data.message);
      }
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  const reset = async () => {
    setLoading(true); setError(''); setLastResult(null);
    setForgeAttempts(0); setForgeSuccesses(0);
    try {
      await fetch(`${API_BASE}/pa5/reset`, { method: 'POST' });
      setHistory([]);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  const fillRandomTag = () => {
    const hex = Array.from({ length: 16 }, () =>
      Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join('');
    setForgeTag(hex);
  };

  const stealTag = () => {
    if (history.length === 0) return;
    // Use a tag from a different message – still won't match the new message
    setForgeTag(history[0].tag);
  };

  return (
    <div className="space-y-4">
      {error && (
        <div className="p-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
          {error}
        </div>
      )}

      {/* Phase 1 – Oracle queries */}
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-lg font-bold mb-1">Phase 1 – Query the Signing Oracle</h3>
        <p className="text-sm text-gray-500 mb-4">
          Request a valid CBC-MAC tag for any message you like. Collect up to as many pairs
          as you need – but you must forge a tag for a <em>new</em> message.
        </p>

        <div className="flex gap-2">
          <input
            type="text"
            value={queryMessage}
            onChange={e => setQueryMessage(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && queryOracle()}
            placeholder="Message to sign (text or hex)…"
            className="flex-1 border border-gray-300 rounded-md p-2 text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500"
          />
          <button
            onClick={queryOracle}
            disabled={loading || !queryMessage.trim()}
            className={`px-4 py-2 text-sm font-bold text-white rounded ${
              loading || !queryMessage.trim() ? 'bg-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'
            }`}
          >
            Get Tag
          </button>
        </div>

        {history.length > 0 && (
          <div className="mt-4 max-h-48 overflow-y-auto space-y-1">
            <div className="text-xs font-semibold text-gray-500 uppercase mb-1">
              Oracle History ({history.length} pairs)
            </div>
            {history.map((entry, i) => (
              <div key={i} className="flex items-center gap-2 text-xs font-mono bg-gray-50 border border-gray-100 rounded p-2">
                <span className="text-gray-400 w-5 shrink-0">{i + 1}.</span>
                <span className="text-gray-700 truncate max-w-xs" title={entry.message}>
                  m = {entry.message}
                </span>
                <span className="text-gray-400 shrink-0">→</span>
                <span className="text-indigo-700 truncate" title={entry.tag}>
                  t = {entry.tag}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Phase 2 – Forgery attempt */}
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-lg font-bold mb-1">Phase 2 – Submit a Forgery</h3>
        <p className="text-sm text-gray-500 mb-4">
          Choose a message <strong>not</strong> in the history above and provide a tag you
          believe will be accepted. The oracle will verify it against the hidden key.
        </p>

        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Target message m*
            </label>
            <input
              type="text"
              value={forgeMessage}
              onChange={e => setForgeMessage(e.target.value)}
              placeholder="A message NOT in the oracle history…"
              className="w-full border border-gray-300 rounded-md p-2 text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Forged tag t* (hex)
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={forgeTag}
                onChange={e => setForgeTag(e.target.value)}
                placeholder="32-char hex tag…"
                className="flex-1 border border-gray-300 rounded-md p-2 text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500"
              />
              <button
                onClick={fillRandomTag}
                className="px-3 py-2 text-xs font-semibold text-gray-700 bg-gray-100 hover:bg-gray-200 border border-gray-300 rounded"
              >
                Random
              </button>
              <button
                onClick={stealTag}
                disabled={history.length === 0}
                className={`px-3 py-2 text-xs font-semibold text-gray-700 border border-gray-300 rounded ${
                  history.length === 0 ? 'bg-gray-50 cursor-not-allowed' : 'bg-yellow-50 hover:bg-yellow-100'
                }`}
              >
                Steal Tag
              </button>
            </div>
            <p className="text-xs text-gray-400 mt-1">
              "Steal Tag" copies an existing tag onto your new message — still gets rejected!
            </p>
          </div>

          <button
            onClick={submitForgery}
            disabled={loading || !forgeMessage.trim() || !forgeTag.trim()}
            className={`w-full py-2 text-sm font-bold text-white rounded ${
              loading || !forgeMessage.trim() || !forgeTag.trim()
                ? 'bg-rose-300 cursor-not-allowed'
                : 'bg-rose-600 hover:bg-rose-700'
            }`}
          >
            Submit Forgery
          </button>
        </div>

        {lastResult && (
          <div className={`mt-4 p-4 rounded-lg border ${
            lastResult.accepted
              ? 'bg-green-50 border-green-300'
              : 'bg-red-50 border-red-200'
          }`}>
            <div className={`text-base font-bold mb-1 ${
              lastResult.accepted ? 'text-green-700' : 'text-red-700'
            }`}>
              {lastResult.accepted
                ? ' Forgery Accepted! (Exceptional – you broke the MAC!)'
                : ' Forgery Rejected'}
            </div>
            {!lastResult.accepted && lastResult.correctTag && (
              <div className="text-xs font-mono text-gray-600 mt-2">
                Correct tag for that message:{' '}
                <span className="text-indigo-700">{lastResult.correctTag}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Stats + Reset */}
      <div className="bg-white p-4 shadow-sm rounded-lg border border-gray-200 flex items-center justify-between">
        <div className="flex gap-6">
          <div>
            <div className="text-xs uppercase text-gray-500 font-bold">Attempts</div>
            <div className="text-2xl font-bold text-gray-800">{forgeAttempts}</div>
          </div>
          <div>
            <div className="text-xs uppercase text-gray-500 font-bold">Successes</div>
            <div className={`text-2xl font-bold ${forgeSuccesses > 0 ? 'text-green-600' : 'text-gray-800'}`}>
              {forgeSuccesses}
            </div>
          </div>
          <div>
            <div className="text-xs uppercase text-gray-500 font-bold">Oracle Pairs</div>
            <div className="text-2xl font-bold text-indigo-700">{history.length}</div>
          </div>
        </div>
        <button
          onClick={reset}
          className="px-4 py-2 text-sm font-bold text-white bg-gray-700 hover:bg-gray-800 rounded"
        >
          Reset &amp; Rotate Key
        </button>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Tab 2 – Length-Extension Attack Demo
// ─────────────────────────────────────────────────────────────────────────────

const LengthExtensionDemo = () => {
  const [message, setMessage]   = useState('data=100');
  const [suffix,  setSuffix]    = useState('&admin=1');
  const [result,  setResult]    = useState<any>(null);
  const [loading, setLoading]   = useState(false);
  const [error,   setError]     = useState('');

  const runAttack = async () => {
    setError(''); setLoading(true); setResult(null);
    try {
      const res  = await fetch(`${API_BASE}/pa5/length-extension`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, suffix }),
      });
      const data = await res.json();
      if (data.status === 'success') setResult(data);
      else setError(data.message);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="space-y-4">
      {error && (
        <div className="p-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
          {error}
        </div>
      )}

      {/* Intro */}
      <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 text-sm text-amber-900">
        <strong>The vulnerability:</strong> A naive MAC <code>t = H(k ‖ m)</code> leaks the
        internal chaining state. An adversary who sees <code>(m, t)</code> can compute a valid tag
        for <code>m ‖ pad ‖ m'</code> by using <code>t</code> as the starting chaining value and
        processing <code>m'</code> — <strong>without knowing the secret key.</strong>
      </div>

      {/* Inputs */}
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-lg font-bold mb-4">Run the Attack</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Original message m (intercepted)
            </label>
            <input
              type="text"
              value={message}
              onChange={e => setMessage(e.target.value)}
              className="w-full border border-gray-300 rounded-md p-2 text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Malicious suffix m'
            </label>
            <input
              type="text"
              value={suffix}
              onChange={e => setSuffix(e.target.value)}
              className="w-full border border-gray-300 rounded-md p-2 text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>
        </div>

        <button
          onClick={runAttack}
          disabled={loading}
          className={`mt-4 px-5 py-2 text-sm font-bold text-white rounded ${
            loading ? 'bg-amber-300 cursor-not-allowed' : 'bg-amber-600 hover:bg-amber-700'
          }`}
        >
          {loading ? 'Computing…' : 'Launch Length-Extension Attack'}
        </button>
      </div>

      {result && (
        <>
          {/* Attack result banner */}
          <div className={`p-4 rounded-lg border ${
            result.attack_success
              ? 'bg-red-50 border-red-300'
              : 'bg-gray-50 border-gray-200'
          }`}>
            <div className={`text-base font-bold ${result.attack_success ? 'text-red-700' : 'text-gray-700'}`}>
              {result.attack_success
                ? '💥 Attack SUCCESS — Forged tag accepted by the server!'
                : 'Attack failed (unexpected)'}
            </div>
            <p className="text-sm mt-1 text-gray-700">{result.explanation}</p>
          </div>

          {/* Step-by-step breakdown */}
          <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200 space-y-4">
            <h3 className="text-base font-bold text-gray-800">Step-by-Step Breakdown</h3>

            <Step number={1} title="Honest sender computes tag for m">
              <KV k="m" v={result.original_message} />
              <KV k="t = H(k ‖ m)" v={result.original_tag} accent />
            </Step>

            <Step number={2} title="Adversary intercepts (m, t) and chooses a suffix">
              <KV k="m'" v={result.suffix} />
              <KV k="MD padding appended to m" v={result.padding_bytes} mono />
              <KV k="Extended message (m ‖ pad ‖ m')" v={result.extended_message_hex} mono small />
            </Step>

            <Step number={3} title="Adversary reuses t as the IV and processes m'">
              <p className="text-xs text-gray-600 mb-2">
                Starting from IV = <span className="font-mono text-indigo-700">{result.original_tag}</span>,
                the adversary runs the hash compression on m' alone — no key needed.
              </p>
              <KV k="Forged tag" v={result.forged_tag} accent />
            </Step>

            <Step number={4} title="Server verification">
              <KV k="Server computes H(k ‖ extended_message)" v={result.server_tag} />
              <KV k="Adversary's forged tag" v={result.forged_tag} />
              <div className={`mt-2 text-sm font-bold ${result.attack_success ? 'text-red-600' : 'text-gray-600'}`}>
                {result.attack_success
                  ? '→ Tags match. Server accepts the forged message.'
                  : '→ Tags do not match.'}
              </div>
            </Step>

            {/* HMAC protection */}
            <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-lg">
              <div className="text-sm font-bold text-green-700 mb-1">
                🛡️ Why HMAC defeats this attack (PA#10)
              </div>
              <p className="text-xs text-green-800">
                HMAC wraps the inner hash in an outer hash keyed with <code>k ⊕ opad</code>:{' '}
                <code>HMAC(k, m) = H((k⊕opad) ‖ H((k⊕ipad) ‖ m))</code>.
                The adversary cannot continue the inner hash from the tag — the outer hash
                hides the internal state. Computing HMAC on the extended message requires
                restarting the <em>inner</em> hash from scratch, which requires the key k.
              </p>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Tab 3 – PRF-MAC vs CBC-MAC comparison
// ─────────────────────────────────────────────────────────────────────────────

const MacCompareDemo = () => {
  const [message, setMessage] = useState('Hello from PA5!');
  const [result,  setResult]  = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  const compute = async () => {
    setError(''); setLoading(true); setResult(null);
    try {
      const res  = await fetch(`${API_BASE}/pa5/compare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });
      const data = await res.json();
      if (data.status === 'success') setResult(data);
      else setError(data.message);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="space-y-4">
      {error && (
        <div className="p-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
          {error}
        </div>
      )}

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-lg font-bold mb-1">PRF-MAC (Fixed-length) vs CBC-MAC (Variable-length)</h3>
        <p className="text-sm text-gray-500 mb-4">
          PRF-MAC simply evaluates <code>F_k(m)</code> — it only handles exactly one block.
          CBC-MAC chains the PRF over every block, producing a single tag for any-length messages.
        </p>

        <div className="flex gap-2">
          <input
            type="text"
            value={message}
            onChange={e => setMessage(e.target.value)}
            placeholder="Any message (text or hex)…"
            className="flex-1 border border-gray-300 rounded-md p-2 text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500"
          />
          <button
            onClick={compute}
            disabled={loading}
            className={`px-4 py-2 text-sm font-bold text-white rounded ${
              loading ? 'bg-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'
            }`}
          >
            {loading ? 'Computing…' : 'Compute Both'}
          </button>
        </div>
      </div>

      {result && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* PRF-MAC */}
          <div className="bg-white p-5 shadow-sm rounded-lg border border-blue-200">
            <div className="text-xs font-bold uppercase text-blue-600 mb-3 tracking-wider">
              PRF-MAC (Fixed-length)
            </div>
            <div className="text-xs font-mono mb-2 text-gray-600">
              Mac(k, m) = F_k(m)
            </div>
            <KV k="Input (16 bytes, padded/truncated)" v={result.prf_mac.input_hex} mono />
            <KV k="Tag" v={result.prf_mac.tag} accent />
            <p className="text-xs text-amber-700 bg-amber-50 border border-amber-100 rounded p-2 mt-3">
              ⚠️ {result.prf_mac.note}. For longer messages, only the first 16 bytes matter —
              the rest are silently ignored.
            </p>
          </div>

          {/* CBC-MAC */}
          <div className="bg-white p-5 shadow-sm rounded-lg border border-green-200">
            <div className="text-xs font-bold uppercase text-green-600 mb-3 tracking-wider">
              CBC-MAC (Variable-length)
            </div>
            <div className="text-xs font-mono mb-2 text-gray-600">
              Mac(k, m) = CBC-chain F_k over blocks
            </div>
            <KV k="Message hex" v={result.message_hex} mono small />
            <KV k="Blocks processed" v={String(result.cbc_mac.block_count)} />
            <KV k="Tag" v={result.cbc_mac.tag} accent />
            <p className="text-xs text-green-700 bg-green-50 border border-green-100 rounded p-2 mt-3">
              ✅ {result.cbc_mac.note}. The final chaining value authenticates the entire message.
            </p>
          </div>

          {/* Security note */}
          <div className="md:col-span-2 bg-white p-5 shadow-sm rounded-lg border border-gray-200">
            <div className="text-xs font-bold uppercase text-gray-500 mb-2 tracking-wider">
              Security comparison
            </div>
            <div className="grid grid-cols-3 text-xs text-center gap-2">
              {[
                ['',              'PRF-MAC',    'CBC-MAC'],
                ['Variable length',   '✗ No',   '✓ Yes'],
                ['Security proof',    'PRF ⇒ MAC', 'PRF ⇒ MAC (chained)'],
                ['Length-extension',  'Vulnerable (fix-len)', 'Vulnerable — use HMAC!'],
              ].map((row, ri) => row.map((cell, ci) => (
                <div
                  key={`${ri}-${ci}`}
                  className={`p-2 rounded ${
                    ri === 0
                      ? 'font-bold bg-gray-100 text-gray-700'
                      : ci === 0
                        ? 'bg-gray-50 text-gray-600 text-left'
                        : 'bg-white border border-gray-100 text-gray-700'
                  }`}
                >
                  {cell}
                </div>
              )))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

const Step = ({ number, title, children }: { number: number; title: string; children: React.ReactNode }) => (
  <div className="flex gap-3">
    <div className="flex-shrink-0 w-6 h-6 rounded-full bg-indigo-100 text-indigo-700 text-xs font-bold flex items-center justify-center mt-0.5">
      {number}
    </div>
    <div className="flex-1">
      <div className="text-sm font-semibold text-gray-700 mb-2">{title}</div>
      {children}
    </div>
  </div>
);

const KV = ({
  k, v, accent = false, mono = false, small = false,
}: {
  k: string; v: string; accent?: boolean; mono?: boolean; small?: boolean;
}) => (
  <div className="mb-1">
    <span className="text-xs text-gray-500">{k}: </span>
    <span
      className={`text-xs font-mono break-all ${
        accent ? 'text-indigo-700 font-semibold' : 'text-gray-800'
      } ${small ? 'text-[10px]' : ''}`}
    >
      {v}
    </span>
  </div>
);

export default PA5Demo;