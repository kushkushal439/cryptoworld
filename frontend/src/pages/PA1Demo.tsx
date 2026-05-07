import React, { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:5000/api';

const PA1Demo: React.FC = () => {
  const [seed, setSeed] = useState('0123456789abcdef');
  const [length, setLength] = useState(16);
  const [outputHex, setOutputHex] = useState('');
  const [bits, setBits] = useState<number[]>([]);
  const [testResults, setTestResults] = useState<any>(null);
  const [ratio, setRatio] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchOutput = async () => {
      setLoading(true);
      try {
        const response = await fetch(`${API_BASE}/pa1/prg`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ seed, length }),
        });
        const data = await response.json();
        
        if (data.output_hex) {
           setOutputHex(data.output_hex);
           setBits(data.bits);
           // Clear old test results
           setTestResults(null);
           setRatio(null);
           setError('');
        } else if (data.message) {
           setError(data.message);
        }
      } catch (err: any) {
        console.error(err);
        setError('Backend Error: Make sure API is running. ' + err.message);
      }
      setLoading(false);
    };
    
    // Add a slightly larger debounce to prevent overlapping slow computations
    const delayDebounceFn = setTimeout(() => {
      fetchOutput();
    }, 500); 
    
    return () => clearTimeout(delayDebounceFn);
  }, [seed, length]);

  const runTests = async () => {
    if (bits.length === 0) return;
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/pa1/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bits }),
      });
      const data = await response.json();
      setTestResults(data.results);
      setRatio(data.ratio);
    } catch (err: any) {
      console.error(err);
      setError('Test Error: ' + err.message);
    }
    setLoading(false);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4">PA#1: PRG Interactive Demo</h2>
        <p className="text-gray-600 mb-6">
          Watch a Pseudo Random Generator (based on DLP OWF) generate bits from a seed.
        </p>

        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-2">
            <label className="block text-sm font-medium text-gray-700">
              Seed <span className="text-gray-500">(Hex string)</span>
            </label>
            <input
              type="text"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono"
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
              placeholder="Enter seed in hex..."
            />
          </div>

          <div className="space-y-4">
            <label className="block text-sm font-medium text-gray-700 mt-2">
              Output Length: {length} bytes
            </label>
            <input
              type="range"
              min="8"
              max="256"
              step="1"
              className="w-full accent-indigo-600 h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
            />
            <div className="flex justify-between text-xs text-gray-500">
              <span>8 bytes</span>
              <span>256 bytes</span>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
         <div className="flex justify-between items-center mb-4">
             <h2 className="text-xl font-bold text-gray-800">Live PRG Output</h2>
             <span className="text-xs font-mono text-gray-500 bg-gray-100 px-2 py-1 rounded">
               {outputHex ? outputHex.length / 2 : 0} bytes
             </span>
         </div>
         
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 font-mono text-sm text-gray-800 break-all h-40 overflow-y-auto mb-6">
          {loading && !outputHex ? 'Generating...' : (outputHex || '...')}
        </div>
         
         <div className="bg-indigo-50 p-4 rounded border border-indigo-100">
             <div className="flex flex-col sm:flex-row sm:items-center gap-6">
                <button
                  onClick={runTests}
                  disabled={loading || bits.length === 0}
                  className={`px-4 py-2 rounded-lg font-bold text-white transition-colors ${
                    loading || bits.length === 0 ? 'bg-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'
                  }`}
                >
                  {loading ? 'Testing...' : 'Randomness Test'}
                </button>
                
                {ratio !== null && (
                    <div className="flex-1 space-y-2">
                       <div className="flex justify-between text-sm font-medium text-indigo-900">
                          <span>Bit Ratio (Ones)</span>
                          <span>{ratio.toFixed(2)}% (50% expected)</span>
                       </div>
                       <div className="w-full bg-indigo-200 rounded-full h-3">
                           <div 
                             className={`h-3 rounded-full ${Math.abs(ratio - 50) < 5 ? 'bg-green-500' : 'bg-red-500'}`}
                             style={{ width: `${ratio}%` }}
                           />
                       </div>
                    </div>
                )}
             </div>
             
             {testResults && (
                 <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                     {Object.entries(testResults).map(([testName, res]: [string, any]) => (
                         <div key={testName} className="bg-white p-4 rounded shadow-sm border border-indigo-100">
                             <h3 className="capitalize text-indigo-800 font-semibold mb-2">{testName.replace('_', ' ')} Test</h3>
                             <div className={`text-xl font-bold ${res.pass ? 'text-green-600' : 'text-red-600'}`}>
                                 {res.pass ? 'PASS' : 'FAIL'}
                             </div>
                             <div className="text-sm text-gray-500 mt-1">
                                 p = {res.p_value.toFixed(4)}
                             </div>
                         </div>
                     ))}
                 </div>
             )}
         </div>
      </div>
    </div>
  );
};

export default PA1Demo;
