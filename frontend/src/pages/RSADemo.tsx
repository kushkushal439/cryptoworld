import { useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

const RSADemo = () => {
  const [message, setMessage] = useState('SEC');
  const [usePkcs, setUsePkcs] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [showRoot, setShowRoot] = useState(false);

  const runAttack = async () => {
    setIsLoading(true);
    setError('');
    setResult(null);
    setShowRoot(false);
    try {
      const res = await fetch(`${API_BASE}/rsa/hastad`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, use_pkcs: usePkcs }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setResult(data);
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4">PA#14: Håstad's Broadcast Attack</h2>
        
        <p className="text-sm text-gray-600 mb-4">
          This visualizer demonstrates how transmitting the same plaintext to 3 different receivers (e=3) using Textbook RSA allows full plaintext recovery via the Chinese Remainder Theorem without needing any private keys.
        </p>

        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Broadcast Message</label>
            <input
              type="text"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="e.g., SECRET"
            />
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              id="paddingToggle"
              className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
              checked={usePkcs}
              onChange={(e) => setUsePkcs(e.target.checked)}
            />
            <label htmlFor="paddingToggle" className="ml-2 block text-sm text-gray-900 font-medium">
              Use PKCS#1 v1.5 Padding
            </label>
          </div>
          
          <button
            onClick={runAttack}
            disabled={isLoading}
            className={`px-4 py-2 font-bold text-white rounded ${isLoading ? 'bg-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'}`}
          >
            {isLoading ? 'Simulating Broadcast...' : 'Launch Broadcast'}
          </button>
        </div>
      </div>

      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[0, 1, 2].map(i => (
              <div key={i} className="bg-gray-50 p-4 shadow-sm rounded-lg border border-gray-200 break-all font-mono text-xs">
                <h3 className="text-md font-bold mb-2 text-gray-800">Recipient {i+1}</h3>
                <p className="text-gray-500 mb-1"><strong>Modulus (N_{i+1}):</strong></p>
                <div className="bg-white p-2 rounded border mb-2 text-[10px]">{result.moduli[i]}</div>
                <p className="text-gray-500 mb-1"><strong>Ciphertext (c_{i+1}):</strong></p>
                <div className="bg-white p-2 rounded border text-[10px] text-blue-800">{result.ciphertexts[i]}</div>
              </div>
            ))}
          </div>

          <div className="bg-red-50 p-6 shadow-sm rounded-lg border border-red-200">
            <h3 className="text-xl font-bold mb-4 text-red-800">Attacker Panel (Live CRT)</h3>
            <div className="space-y-4">
              <div>
                <p className="text-sm font-medium text-gray-700">1. Recovered Intermediate (m³ mod N₁N₂N₃) via CRT:</p>
                <div className="mt-1 bg-white border border-red-200 p-3 rounded font-mono text-sm break-all text-red-900 shadow-inner">
                  {result.m_pow_e}
                </div>
              </div>

              {!showRoot ? (
                <button
                  onClick={() => setShowRoot(true)}
                  className="w-full py-3 bg-red-600 hover:bg-red-700 text-white font-bold rounded-lg shadow transition-colors"
                >
                  Cube Root
                </button>
              ) : (
                <div className="p-4 bg-red-100 rounded-lg border border-red-300">
                  <p className="text-sm font-medium text-red-800 mb-1">2. Integer Cube Root (Recovered Plaintext/Garbage):</p>
                  <div className="bg-white border p-3 rounded font-mono text-sm break-all mb-1 text-gray-800">
                    <span className="text-xs text-gray-500 uppercase tracking-wide">Integer:</span> {result.recovered_m}
                  </div>
                  <div className="bg-white border p-3 rounded font-mono text-sm break-all mb-3 text-blue-800">
                    <span className="text-xs text-blue-500 uppercase tracking-wide">Decoded String:</span> "{result.recovered_str || result.recovered_m}"
                  </div>
                  
                  {result.result === 'SUCCESS' ? (
                    <div className="flex items-center text-green-700 font-bold bg-green-100 p-3 rounded">
                      <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                      SUCCESS: Plaintext perfectly matches original message integer ({result.message_int}).
                    </div>
                  ) : (
                    <div className="flex flex-col text-red-700 bg-red-200 p-4 rounded-lg">
                      <div className="flex items-center font-bold mb-2">
                        <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                        FAILED: Integer cube root does not match original message.
                      </div>
                      <p className="text-sm">The PKCS#1 v1.5 padding injected randomness, so each ciphertext encrypted a <em>different</em> padded integer. The CRT math resolved the congruences, but the result is completely destroyed and the cube root yields garbage!</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RSADemo;
