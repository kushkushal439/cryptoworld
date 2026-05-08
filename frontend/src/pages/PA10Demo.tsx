import { useState } from 'react';

const toHex = (str: string) => Array.from(new TextEncoder().encode(str)).map(b => b.toString(16).padStart(2, '0')).join('');

const API_BASE = 'http://localhost:5000/api';

const PA10Demo = () => {
  const [message, setMessage] = useState('data=100');
  const [suffix, setSuffix] = useState('&admin=1');
  const [hashType, setHashType] = useState<'DLP' | 'SHA256'>('DLP');
  
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const runAttack = async () => {
    setError('');
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch(`${API_BASE}/pa10/length-extension`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, suffix, hash_type: hashType }),
      });
      const data = await res.json();
      if (data.status === 'success') setResult(data);
      else setError(data.message);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-1">PA#10: Length-Extension vs HMAC</h2>
        <p className="text-sm text-gray-500">
          Compare the vulnerability of a Naive Hash MAC against the robust double-hash structure of HMAC.
        </p>
      </div>

      {error && (
        <div className="p-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
          {error}
        </div>
      )}

      {/* Inputs & Controls */}
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <div className="flex flex-col md:flex-row md:items-end gap-4">
          <div className="flex-1">
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Original message (m)
            </label>
            <input
              type="text"
              value={message}
              onChange={e => setMessage(e.target.value)}
              className="w-full border border-gray-300 rounded-md p-2 text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>
          <div className="flex-1">
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Malicious suffix (m')
            </label>
            <input
              type="text"
              value={suffix}
              onChange={e => setSuffix(e.target.value)}
              className="w-full border border-gray-300 rounded-md p-2 text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>
          <div className="flex-none">
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Underlying Hash
            </label>
            <div className="flex bg-gray-100 rounded-md p-1 w-full max-w-[200px]">
              <button
                onClick={() => setHashType('DLP')}
                className={`flex-1 text-xs font-bold py-1.5 px-3 rounded transition-colors ${
                  hashType === 'DLP' ? 'bg-white shadow text-indigo-700' : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                DLP Hash
              </button>
              <button
                onClick={() => setHashType('SHA256')}
                className={`flex-1 text-xs font-bold py-1.5 px-3 rounded transition-colors ${
                  hashType === 'SHA256' ? 'bg-white shadow text-indigo-700' : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                SHA-256
              </button>
            </div>
          </div>
          <div className="flex-none">
            <button
              onClick={runAttack}
              disabled={loading || !message || !suffix}
              className={`px-5 py-2 w-full text-sm font-bold text-white rounded ${
                loading || !message || !suffix ? 'bg-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'
              }`}
            >
              {loading ? 'Computing…' : 'Run Attack'}
            </button>
          </div>
        </div>
      </div>

      {result && (
        <>
          {/* Extended Message Info */}
          <div className="bg-gray-50 p-4 border border-gray-200 rounded-lg text-sm">
            <div className="font-semibold text-gray-700 mb-2">Extended Message Construction:</div>
            <div className="flex flex-wrap gap-x-2 gap-y-1 font-mono text-xs items-center">
              <span className="text-gray-500">m =</span>
              <span className="text-blue-600 break-all">{toHex(result.message)}</span>
              <span className="text-gray-400">‖</span>
              <span className="text-gray-500">pad =</span>
              <span className="text-amber-600 break-all">{result.padding_hex}</span>
              <span className="text-gray-400">‖</span>
              <span className="text-gray-500">m' =</span>
              <span className="text-red-600 break-all">{toHex(result.suffix)}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Left Column: Naive Hash */}
            <div className="bg-white shadow-sm rounded-lg border border-red-200 flex flex-col">
              <div className="bg-red-50 p-4 border-b border-red-200 rounded-t-lg">
                <h3 className="text-lg font-bold text-red-800 flex items-center justify-between">
                  <span>Naive MAC</span>
                  <span className="text-xs bg-red-200 text-red-900 px-2 py-1 rounded font-mono">
                    t = H(k ‖ m)
                  </span>
                </h3>
                <p className="text-xs text-red-700 mt-1">
                  Vulnerable to length-extension. State is easily continued.
                </p>
              </div>
              <div className="p-5 flex-1 space-y-4">
                <KV k="1. Honest sender computes" v={result.naive.honest_tag} accent />
                
                <div className="border-l-2 border-red-300 pl-3 py-1 my-2">
                  <p className="text-xs text-gray-600">
                    <strong>Adversary</strong> uses the honest tag as the IV and hashes the malicious suffix <span className="font-mono text-red-600 text-[10px]">m'</span> without knowing <span className="font-mono text-gray-500 text-[10px]">k</span>.
                  </p>
                </div>
                
                <KV k="2. Adversary forged tag" v={result.naive.forged_tag} />
                <KV k="3. Server verification" v={result.naive.server_tag} />
                
                <div className={`mt-4 p-3 rounded text-center font-bold text-sm ${
                  result.naive.success ? 'bg-red-100 text-red-800 border border-red-300' : 'bg-gray-100 text-gray-600'
                }`}>
                  {result.naive.success ? '💥 Forgery Succeeded!' : 'Forgery Failed (Unexpected)'}
                </div>
              </div>
            </div>

            {/* Right Column: HMAC */}
            <div className="bg-white shadow-sm rounded-lg border border-green-200 flex flex-col">
              <div className="bg-green-50 p-4 border-b border-green-200 rounded-t-lg">
                <h3 className="text-lg font-bold text-green-800 flex items-center justify-between">
                  <span>HMAC</span>
                  <span className="text-xs bg-green-200 text-green-900 px-2 py-1 rounded font-mono">
                    t = H(k⊕opad ‖ H(k⊕ipad ‖ m))
                  </span>
                </h3>
                <p className="text-xs text-green-700 mt-1">
                  Secure against length-extension. Internal state is hidden by the outer hash.
                </p>
              </div>
              <div className="p-5 flex-1 space-y-4">
                <KV k="1. Honest sender computes" v={result.hmac.honest_tag} accent />
                
                <div className="border-l-2 border-green-300 pl-3 py-1 my-2">
                  <p className="text-xs text-gray-600">
                    <strong>Adversary</strong> tries to extend the HMAC tag directly. Because the internal state of the inner hash is hidden, they are blocked.
                  </p>
                </div>
                
                <KV k="2. Adversary forged tag" v={result.hmac.forged_tag} />
                <KV k="3. Server verification" v={result.hmac.server_tag} />
                
                <div className={`mt-4 p-3 rounded text-center font-bold text-sm ${
                  !result.hmac.success ? 'bg-green-100 text-green-800 border border-green-300' : 'bg-red-100 text-red-800'
                }`}>
                  {!result.hmac.success ? '🛡️ Forgery Failed!' : 'Forgery Succeeded (Unexpected)'}
                </div>
              </div>
            </div>

          </div>
        </>
      )}
    </div>
  );
};

const KV = ({ k, v, accent = false }: { k: string; v: string; accent?: boolean }) => (
  <div>
    <div className="text-xs text-gray-500 font-semibold uppercase tracking-wider mb-1">{k}</div>
    <div className={`text-xs font-mono break-all p-2 rounded border ${
      accent ? 'bg-indigo-50 border-indigo-200 text-indigo-700' : 'bg-gray-50 border-gray-200 text-gray-800'
    }`}>
      {v || <span className="text-gray-400 italic">None</span>}
    </div>
  </div>
);

export default PA10Demo;
