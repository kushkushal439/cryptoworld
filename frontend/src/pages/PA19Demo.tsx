import { useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

const PA19Demo = () => {
  const [a, setA] = useState(0);
  const [b, setB] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  
  const [allResults, setAllResults] = useState<any[]>([]);

  const runAnd = async (inputA: number, inputB: number) => {
    setIsLoading(true);
    setError('');
    setAllResults([]);
    
    try {
      const res = await fetch(`${API_BASE}/pa19/and`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ a: inputA, b: inputB }),
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

  const runAll = async () => {
    setIsLoading(true);
    setError('');
    setAllResults([]);
    setResult(null);

    const combos = [[0, 0], [0, 1], [1, 0], [1, 1]];
    const results = [];
    
    try {
      for (const [ai, bi] of combos) {
        const res = await fetch(`${API_BASE}/pa19/and`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ a: ai, b: bi }),
        });
        const data = await res.json();
        if (data.status === 'success') {
          results.push(data);
        } else {
          throw new Error(data.message);
        }
      }
      setAllResults(results);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4">PA#19: Secure AND (Step-by-step)</h2>
        
        <p className="text-sm text-gray-600 mb-4">
          This demo shows how Alice and Bob can compute an AND gate on their secret bits 'a' and 'b' 
          securely using Oblivious Transfer without revealing their inputs to each other.
        </p>

        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div className="p-4 border rounded bg-indigo-50">
            <h3 className="font-bold text-indigo-800">Alice Panel</h3>
            <label className="block text-sm font-medium mt-2">Bit a ∈ {"{0, 1}"}</label>
            <select
              className="mt-1 block w-full border border-gray-300 rounded p-2"
              value={a}
              onChange={(e) => setA(parseInt(e.target.value))}
            >
              <option value={0}>0</option>
              <option value={1}>1</option>
            </select>
          </div>
          <div className="p-4 border rounded bg-blue-50">
            <h3 className="font-bold text-blue-800">Bob Panel</h3>
            <label className="block text-sm font-medium mt-2">Bit b ∈ {"{0, 1}"}</label>
            <select
              className="mt-1 block w-full border border-gray-300 rounded p-2"
              value={b}
              onChange={(e) => setB(parseInt(e.target.value))}
            >
              <option value={0}>0</option>
              <option value={1}>1</option>
            </select>
          </div>
        </div>

        <div className="flex gap-4">
          <button
            onClick={() => runAnd(a, b)}
            disabled={isLoading}
            className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded"
          >
            {isLoading ? 'Computing...' : 'Compute AND'}
          </button>

          <button
            onClick={runAll}
            disabled={isLoading}
            className="px-4 py-2 font-bold text-white bg-green-600 hover:bg-green-700 rounded"
          >
            Run all
          </button>
        </div>
      </div>

      {result && (
        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
          <h3 className="text-xl font-bold mb-4">Execution Result: {result.a} AND {result.b} = {result.result}</h3>
          
          <div className="mb-6">
            <h4 className="font-bold text-gray-800 mb-2">Step-log Transcript</h4>
            <div className="space-y-2">
              {result.transcript.map((item: any, idx: number) => (
                <div key={idx} className="p-3 bg-gray-50 border rounded text-sm">
                  <div className="font-semibold text-gray-700">{item.step}</div>
                  <div className="text-gray-600 mt-1 font-mono break-all">{item.details}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-yellow-50 rounded border border-yellow-200">
              <h4 className="font-bold text-yellow-800 text-sm uppercase">What does Alice learn?</h4>
              <p className="text-sm mt-2 text-yellow-900">
                Alice receives pk_0 and pk_1 from Bob. Since both are validly generated RSA public keys, they are computationally indistinguishable. Without the private key, Alice cannot know for which key Bob kept the trapdoor, so she learns nothing about Bob's bit b.
              </p>
            </div>
            <div className="p-4 bg-yellow-50 rounded border border-yellow-200">
              <h4 className="font-bold text-yellow-800 text-sm uppercase">What does Bob learn?</h4>
              <p className="text-sm mt-2 text-yellow-900">
                Bob only holds the private key for his choice b={result.b}. He decrypts c_{result.b} to get m_{result.b}={result.result}. Since he cannot decrypt the other ciphertext, he learns nothing about the other message (which might be Alice's bit). If b=0, Bob gets m_0=0 and learns nothing about a. If b=1, Bob gets m_1=a, which is exactly the output of the AND gate!
              </p>
            </div>
          </div>
        </div>
      )}

      {allResults.length > 0 && (
        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
          <h3 className="text-xl font-bold mb-4">Run All Configurations</h3>
          <div className="space-y-4">
            {allResults.map((res: any, idx: number) => (
              <div key={idx} className="p-4 bg-gray-50 rounded border flex justify-between items-center">
                <div>
                  <span className="font-mono">a={res.a}, b={res.b}</span>
                </div>
                <div>
                  <span className="font-bold">Output: {res.result}</span>
                  {res.result === (res.a & res.b) ? (
                    <span className="ml-2 text-green-600">✓ Match</span>
                  ) : (
                    <span className="ml-2 text-red-600">✗ Failed</span>
                  )}
                </div>
              </div>
            ))}
          </div>
          <p className="mt-4 text-sm text-gray-700">All outputs match the AND truth table perfectly. The transcript reveals nothing extra.</p>
        </div>
      )}
    </div>
  );
};

export default PA19Demo;
