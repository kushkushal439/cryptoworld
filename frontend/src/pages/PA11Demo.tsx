import { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:5000/api';

const randomHex = () => Array.from(crypto.getRandomValues(new Uint32Array(1))).map(b => b.toString(16)).join('');

const PA11Demo = () => {
  const [params, setParams] = useState<any>(null);
  const [a, setA] = useState('');
  const [b, setB] = useState('');
  const [eKey, setEKey] = useState('');
  
  const [isMitm, setIsMitm] = useState(false);
  const [phase, setPhase] = useState(0); // 0: input, 1: compute pub, 2: transit, 3: derived
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');

  // Fetch parameters on mount
  useEffect(() => {
    fetch(`${API_BASE}/pa11/params`)
      .then(r => r.json())
      .then(data => {
        if (data.status === 'success') {
          setParams(data.params);
          setA(randomHex());
          setB(randomHex());
          setEKey(randomHex());
        }
      });
  }, []);

  const handleExchange = async () => {
    setError('');
    setPhase(0);
    try {
      const payload = { p: params.p_hex, g: params.g_hex, a, b, is_mitm: isMitm, ...(isMitm && { e: eKey }) };
      const res = await fetch(`${API_BASE}/pa11/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      
      if (data.status === 'success') {
        setResult(data);
        // Animate the phases
        setPhase(1);
        setTimeout(() => setPhase(2), 1000);
        setTimeout(() => setPhase(3), 2000);
      } else {
        setError(data.message);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleReset = () => {
    setPhase(0);
    setResult(null);
  };

  if (!params) return <div className="p-8 text-center text-gray-500">Generating Group Parameters...</div>;

  const secretsMatch = result && result.K_Alice_hex === result.K_Bob_hex;

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header & Parameters */}
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-2xl font-bold mb-1">PA#11: Live Diffie-Hellman Key Exchange</h2>
            <p className="text-sm text-gray-500 mb-4">
              Watch a key exchange in real-time, and see how a Man-in-the-Middle attack breaks it.
            </p>
          </div>
          <div className="flex items-center gap-2 bg-red-50 text-red-800 px-4 py-2 rounded-lg border border-red-200">
            <input 
              type="checkbox" 
              id="mitm"
              className="w-5 h-5 text-red-600 rounded focus:ring-red-500 cursor-pointer"
              checked={isMitm}
              onChange={(e) => { setIsMitm(e.target.checked); handleReset(); }}
              disabled={phase > 0 && phase < 3}
            />
            <label htmlFor="mitm" className="font-bold cursor-pointer">Enable Eve (MITM Attack)</label>
          </div>
        </div>

        <div className="flex gap-4 p-3 bg-gray-50 rounded border border-gray-200 text-sm font-mono break-all">
          <div className="flex-1"><span className="font-bold text-gray-700">p:</span> {params.p_hex}</div>
          <div className="flex-1"><span className="font-bold text-gray-700">g:</span> {params.g_hex}</div>
        </div>
      </div>

      {error && <div className="p-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">{error}</div>}

      {/* Main Exchange Arena */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* ALICE */}
        <div className="bg-white shadow-sm rounded-lg border border-blue-200 flex flex-col">
          <div className="bg-blue-50 p-4 border-b border-blue-200 rounded-t-lg font-bold text-blue-800 text-center text-lg">
            Alice
          </div>
          <div className="p-5 flex-1 space-y-4">
            <div>
              <label className="block text-xs font-bold text-gray-600 mb-1">Private Exponent (secret_a)</label>
              <div className="flex gap-2">
                <input 
                  className="w-full border border-gray-300 rounded p-2 text-sm font-mono" 
                  value={a} onChange={e => setA(e.target.value)} disabled={phase > 0} 
                />
                <button 
                  onClick={() => setA(randomHex())} disabled={phase > 0}
                  className="px-3 bg-gray-100 hover:bg-gray-200 text-gray-600 rounded border border-gray-300 text-xs font-bold"
                >
                  RND
                </button>
              </div>
            </div>

            <div className={`transition-opacity duration-500 ${phase >= 1 ? 'opacity-100' : 'opacity-0'}`}>
              <div className="text-xs text-gray-500 font-bold uppercase mb-1">Public Key (pub_A = g^secret_a mod p)</div>
              <div className="p-2 bg-blue-100 text-blue-900 border border-blue-300 rounded text-sm font-mono break-all">
                {result?.A_hex}
              </div>
            </div>

            <div className={`transition-opacity duration-500 ${phase >= 3 ? 'opacity-100' : 'opacity-0'}`}>
              <div className="text-xs text-gray-500 font-bold uppercase mb-1">Derived Secret (K = {isMitm ? "pub_B'^secret_a" : "pub_B^secret_a"} mod p)</div>
              <div className={`p-2 border rounded text-sm font-mono break-all font-bold ${
                secretsMatch ? 'bg-green-100 text-green-900 border-green-300' : 'bg-red-100 text-red-900 border-red-300'
              }`}>
                {result?.K_Alice_hex}
              </div>
            </div>
          </div>
        </div>

        {/* EVE / TRANSIT */}
        <div className="flex flex-col items-center justify-center space-y-4">
          
          {phase === 0 && (
            <button
              onClick={handleExchange}
              disabled={!a || !b || (isMitm && !eKey)}
              className="px-8 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-full shadow-lg transition transform hover:scale-105"
            >
              Exchange!
            </button>
          )}

          {phase > 0 && phase < 3 && (
            <div className="text-sm font-bold text-indigo-600 animate-pulse text-center">
              {phase === 1 && "Computing Public Keys..."}
              {phase === 2 && (isMitm ? "Eve Intercepting!" : "Keys in Transit...")}
            </div>
          )}

          {phase === 3 && (
            <button
              onClick={handleReset}
              className="px-6 py-2 bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold rounded shadow transition"
            >
              Reset
            </button>
          )}

          {isMitm && (
            <div className="w-full bg-white shadow-sm rounded-lg border border-red-300 flex flex-col mt-4">
              <div className="bg-red-100 p-2 border-b border-red-300 rounded-t-lg font-bold text-red-800 text-center">
                Eve
              </div>
              <div className="p-4 flex-1 space-y-4">
                <div>
                  <label className="block text-xs font-bold text-gray-600 mb-1">Private Exponent (secret_e)</label>
                  <div className="flex gap-2">
                    <input 
                      className="w-full border border-gray-300 rounded p-1 text-xs font-mono" 
                      value={eKey} onChange={e => setEKey(e.target.value)} disabled={phase > 0} 
                    />
                    <button 
                      onClick={() => setEKey(randomHex())} disabled={phase > 0}
                      className="px-2 bg-gray-100 text-gray-600 rounded border border-gray-300 text-xs font-bold"
                    >
                      RND
                    </button>
                  </div>
                </div>

                <div className={`transition-opacity duration-500 ${phase >= 2 ? 'opacity-100' : 'opacity-0'}`}>
                  <div className="text-[10px] text-gray-500 font-bold uppercase mb-1 text-center">Spoofed Keys Sent</div>
                  <div className="flex gap-2">
                    <div className="flex-1 p-1 bg-red-50 border border-red-200 rounded text-[10px] font-mono break-all text-center">
                      pub_A' ➞ Bob
                    </div>
                    <div className="flex-1 p-1 bg-red-50 border border-red-200 rounded text-[10px] font-mono break-all text-center">
                      pub_B' ➞ Alice
                    </div>
                  </div>
                </div>

                <div className={`transition-opacity duration-500 ${phase >= 3 ? 'opacity-100' : 'opacity-0'}`}>
                  <div className="text-[10px] text-gray-500 font-bold uppercase mb-1">Stolen Secrets</div>
                  <div className="space-y-1">
                    <div className="p-1 bg-red-100 border border-red-300 rounded text-[10px] font-mono break-all font-bold">
                      <span className="text-gray-500 font-normal">w/ Alice:</span> {result?.K_Eve_Alice_hex}
                    </div>
                    <div className="p-1 bg-red-100 border border-red-300 rounded text-[10px] font-mono break-all font-bold">
                      <span className="text-gray-500 font-normal">w/ Bob:</span> {result?.K_Eve_Bob_hex}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>

        {/* BOB */}
        <div className="bg-white shadow-sm rounded-lg border border-purple-200 flex flex-col">
          <div className="bg-purple-50 p-4 border-b border-purple-200 rounded-t-lg font-bold text-purple-800 text-center text-lg">
            Bob
          </div>
          <div className="p-5 flex-1 space-y-4">
            <div>
              <label className="block text-xs font-bold text-gray-600 mb-1">Private Exponent (secret_b)</label>
              <div className="flex gap-2">
                <input 
                  className="w-full border border-gray-300 rounded p-2 text-sm font-mono" 
                  value={b} onChange={e => setB(e.target.value)} disabled={phase > 0} 
                />
                <button 
                  onClick={() => setB(randomHex())} disabled={phase > 0}
                  className="px-3 bg-gray-100 hover:bg-gray-200 text-gray-600 rounded border border-gray-300 text-xs font-bold"
                >
                  RND
                </button>
              </div>
            </div>

            <div className={`transition-opacity duration-500 ${phase >= 1 ? 'opacity-100' : 'opacity-0'}`}>
              <div className="text-xs text-gray-500 font-bold uppercase mb-1">Public Key (pub_B = g^secret_b mod p)</div>
              <div className="p-2 bg-purple-100 text-purple-900 border border-purple-300 rounded text-sm font-mono break-all">
                {result?.B_hex}
              </div>
            </div>

            <div className={`transition-opacity duration-500 ${phase >= 3 ? 'opacity-100' : 'opacity-0'}`}>
              <div className="text-xs text-gray-500 font-bold uppercase mb-1">Derived Secret (K = {isMitm ? "pub_A'^secret_b" : "pub_A^secret_b"} mod p)</div>
              <div className={`p-2 border rounded text-sm font-mono break-all font-bold ${
                secretsMatch ? 'bg-green-100 text-green-900 border-green-300' : 'bg-red-100 text-red-900 border-red-300'
              }`}>
                {result?.K_Bob_hex}
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};

export default PA11Demo;
