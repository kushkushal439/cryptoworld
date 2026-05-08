import { useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

const PRELOADS = {
  carmichael: "561",
  prime512: "13395381880000738486199981446889131672446795361920025054759057407408392497029236867046426359412822485006049184785025883835210200964728872725321450626130787",
  composite512: "6641363510255799073938112425779716530404183044754984598176380869016417022237850923251920110320043304958574462310650145796171218681932369334256000992623443"
};

const PA13Demo = () => {
  const [n, setN] = useState('561');
  const [k, setK] = useState<number>(10);
  
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const runTest = async () => {
    setError('');
    setLoading(true);
    setResult(null);
    try {
      // Validate input contains only digits or is valid hex
      if (!n.match(/^(0x)?[0-9a-fA-F]+$/)) {
        throw new Error("Input must be a valid integer or hex string.");
      }
      
      const res = await fetch(`${API_BASE}/pa13/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ n, k }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setResult(data.result);
      } else {
        setError(data.message);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-1">PA#13: Miller-Rabin Primality Tester</h2>
        <p className="text-sm text-gray-500">
          Trace the probabilistic Miller-Rabin test round-by-round. Witness how it catches pseudoprimes like Carmichael numbers.
        </p>
      </div>

      {error && (
        <div className="p-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
          {error}
        </div>
      )}

      {/* Controls */}
      <div className="bg-white shadow-sm rounded-lg border border-gray-200 flex flex-col">
        <div className="bg-gray-50 p-3 border-b border-gray-200 flex flex-wrap gap-2 items-center">
          <span className="text-xs font-bold text-gray-500 uppercase">Pre-loaded:</span>
          <button onClick={() => setN(PRELOADS.carmichael)} className="px-3 py-1 bg-white border border-gray-300 rounded text-xs font-bold hover:bg-indigo-50 hover:text-indigo-700 transition">
            561 (Carmichael)
          </button>
          <button onClick={() => setN(PRELOADS.prime512)} className="px-3 py-1 bg-white border border-gray-300 rounded text-xs font-bold hover:bg-green-50 hover:text-green-700 transition">
            512-bit Prime
          </button>
          <button onClick={() => setN(PRELOADS.composite512)} className="px-3 py-1 bg-white border border-gray-300 rounded text-xs font-bold hover:bg-red-50 hover:text-red-700 transition">
            512-bit Composite
          </button>
        </div>
        
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-bold text-gray-700 mb-1">Number to Test (n)</label>
            <textarea
              className="w-full border border-gray-300 rounded-lg p-3 text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500 min-h-[80px]"
              value={n}
              onChange={e => setN(e.target.value)}
              placeholder="Enter an integer..."
            />
          </div>
          
          <div className="flex items-center gap-6">
            <div className="flex-1">
              <label className="block text-sm font-bold text-gray-700 mb-2">
                Rounds (k = {k})
              </label>
              <input 
                type="range" min="1" max="40" 
                value={k} onChange={e => setK(parseInt(e.target.value))} 
                className="w-full"
              />
              <div className="flex justify-between text-xs text-gray-500 mt-1">
                <span>1</span>
                <span>Error Prob &le; 4^{k === 1 ? '-1' : '-' + k}</span>
                <span>40</span>
              </div>
            </div>
            
            <button
              onClick={runTest}
              disabled={loading || !n}
              className={`px-8 py-3 font-bold text-white rounded-lg shadow ${
                loading || !n ? 'bg-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'
              }`}
            >
              {loading ? 'Testing...' : 'Run Test'}
            </button>
          </div>
        </div>
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-4">
          <div className={`p-6 rounded-lg border-2 flex items-center justify-between ${
            result.verdict === 'PROBABLY PRIME' ? 'bg-green-50 border-green-500 text-green-900' : 'bg-red-50 border-red-500 text-red-900'
          }`}>
            <div>
              <h3 className="text-3xl font-black uppercase tracking-wider">{result.verdict}</h3>
              <p className="text-sm mt-1 opacity-80 font-medium">{result.reason}</p>
            </div>
            <div className="text-right">
              <div className="text-sm font-bold opacity-75 uppercase">Execution Time</div>
              <div className="text-xl font-mono">{result.time_ms} ms</div>
            </div>
          </div>

          <div className="bg-white shadow-sm rounded-lg border border-gray-200 overflow-hidden">
            <div className="bg-gray-50 p-4 border-b border-gray-200 font-bold text-gray-700 flex justify-between">
              <span>Execution Trace (n-1 = 2^{result.s} × {result.d_hex})</span>
              <span className="text-gray-500 text-sm">Tested {result.rounds.length} witnesses</span>
            </div>
            
            <div className="divide-y divide-gray-200 max-h-[600px] overflow-y-auto">
              {result.rounds.map((r: any, idx: number) => (
                <div key={idx} className={`p-4 ${r.caught_by_square_root ? 'bg-orange-50' : ''}`}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-bold text-indigo-800">Round {r.round}</div>
                    <div className={`text-xs font-bold px-2 py-1 rounded ${
                      r.outcome.includes('PASS') ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                    }`}>
                      {r.outcome}
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <div className="text-xs font-bold text-gray-500 uppercase mb-1">Witness (a)</div>
                      <div className="text-xs font-mono bg-gray-100 p-2 rounded break-all">{r.a}</div>
                    </div>
                    <div>
                      <div className="text-xs font-bold text-gray-500 uppercase mb-1">Naive Fermat Test (a^n-1)</div>
                      <div className={`text-xs font-mono p-2 rounded break-all border ${
                        r.fermat_pass ? 'bg-red-100 border-red-300 text-red-800' : 'bg-green-100 border-green-300 text-green-800'
                      }`}>
                        {r.fermat_pass ? '1 (FOOLED!)' : '!= 1 (Caught)'}
                      </div>
                    </div>
                  </div>

                  <div className="mt-3">
                    <div className="text-xs font-bold text-gray-500 uppercase mb-1">Miller-Rabin Sequence</div>
                    <div className="flex flex-wrap gap-2">
                      {r.sequence.map((x: string, i: number) => (
                        <div key={i} className="flex items-center gap-2">
                          <div className="text-[10px] font-mono bg-blue-50 text-blue-800 p-1 rounded border border-blue-200 max-w-[200px] truncate" title={x}>
                            {i === 0 ? 'x = a^d' : `x^2`} ➞ {x.length > 20 ? x.substring(0, 15) + '...' : x}
                          </div>
                          {i < r.sequence.length - 1 && <span className="text-gray-300">→</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                  
                  {r.caught_by_square_root && (
                    <div className="mt-3 p-2 bg-orange-100 border border-orange-300 text-orange-800 text-xs font-bold rounded">
                      ⚠️ Miller-Rabin detected a non-trivial square root of 1 here! The Fermat test was fooled, but the squaring loop caught the compositeness.
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PA13Demo;
