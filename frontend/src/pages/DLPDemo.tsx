import { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:5000/api';

const DLPDemo = () => {
  const [message, setMessage] = useState('');
  const [toyHash, setToyHash] = useState('');
  const [fullHash, setFullHash] = useState('');
  const [error, setError] = useState('');

  const [isHunting, setIsHunting] = useState(false);
  const [collisionResult, setCollisionResult] = useState<any>(null);

  const fetchHash = async () => {
    try {
      const res = await fetch(`${API_BASE}/dlp/hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setToyHash(data.toy_hash);
        setFullHash(data.full_hash);
        setError('');
      } else {
        setError(data.message);
      }
    } catch (err: any) {
      setError('Error connecting to backend: ' + err.message);
    }
  };

  useEffect(() => {
    const delayDebounceFn = setTimeout(() => {
      fetchHash();
    }, 300); // 300ms debounce
    return () => clearTimeout(delayDebounceFn);
  }, [message]);

  const huntCollision = async () => {
    setIsHunting(true);
    setCollisionResult(null);
    try {
      const res = await fetch(`${API_BASE}/dlp/collision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      if (data.status === 'success') {
        setCollisionResult(data);
        setError('');
      } else {
        setError(data.message);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsHunting(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4">PA#8: DLP Hash Live</h2>
        
        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Input Message</label>
            <input
              type="text"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Type anything..."
            />
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-blue-50 rounded border border-blue-100">
              <h3 className="text-sm font-semibold text-blue-700 uppercase">Toy Hash (16-bit q)</h3>
              <p className="mt-2 font-mono text-blue-900 break-all">{toyHash || '...'}</p>
            </div>
            
            <div className="p-4 bg-green-50 rounded border border-green-100">
              <h3 className="text-sm font-semibold text-green-700 uppercase">Normal Hash (64-bit q)</h3>
              <p className="mt-2 font-mono text-green-900 break-all">{fullHash || '...'}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-xl font-bold mb-4 text-purple-800">Birthday Attack: Collision Hunt</h2>
        <p className="text-sm text-gray-600 mb-4">
          Using the toy parameters (q ≈ 2¹⁶), we expect a collision in roughly √q ≈ 181 tries. 
          Let's brute-force variables x and y randomly until we find a match!
        </p>

        <button
          onClick={huntCollision}
          disabled={isHunting}
          className={`px-4 py-2 font-bold text-white rounded ${isHunting ? 'bg-purple-300 cursor-not-allowed' : 'bg-purple-600 hover:bg-purple-700'}`}
        >
          {isHunting ? 'Hunting...' : 'Start Collision Hunt'}
        </button>

        {collisionResult && (
          <div className="mt-6 space-y-4">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-sm font-medium text-purple-700 text-purple-700">Progress</span>
                <span className="text-sm font-medium text-purple-700 text-purple-700">{collisionResult.tries} tries</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2.5">
                <div 
                  className="bg-purple-600 h-2.5 rounded-full" 
                  style={{ width: `${Math.min(100, (collisionResult.tries / collisionResult.target_tries) * 100)}%` }}
                ></div>
              </div>
              <p className="text-xs text-gray-500 mt-1">Found after {collisionResult.tries} hashes. Expected: ~{collisionResult.target_tries}</p>
            </div>

            <div className="p-4 bg-red-50 border border-red-200 rounded">
              <h3 className="text-red-800 font-bold mb-2">💥 Collision Found!</h3>
              <ul className="list-disc list-inside text-sm text-gray-800 ml-4 space-y-1">
                <li>Input 1: <span className="font-mono bg-white px-1">x={collisionResult.x1}, y={collisionResult.y1}</span></li>
                <li>Input 2: <span className="font-mono bg-white px-1">x={collisionResult.x2}, y={collisionResult.y2}</span></li>
                <li>Shared Hash Output: <span className="font-mono font-bold">{collisionResult.output}</span></li>
              </ul>
              
              <div className="mt-4 p-3 bg-red-100 rounded text-sm text-red-900 border border-red-200">
                <p><strong>Fatal Cryptographic Consequence:</strong></p>
                <p className="mt-1">By finding this collision, the math implicitly solves the Discrete Logarithm: <code>α = (x₁ - x₂) * (y₂ - y₁)⁻¹ mod q</code></p>
                <p className="mt-1">Calculated Secret α = <span className="font-bold">{collisionResult.recovered_alpha}</span></p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DLPDemo;
