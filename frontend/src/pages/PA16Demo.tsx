import { useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

const PA16Demo = () => {
  const [message, setMessage] = useState('42');
  const [cipher, setCipher] = useState<{ c1: string; c2: string; p: string; m: string } | null>(null);
  const [decrypted, setDecrypted] = useState<string>('');
  const [malleated, setMalleated] = useState<{ c1: string; c2: string; m: string } | null>(null);
  const [successCount, setSuccessCount] = useState(0);
  const [attempts, setAttempts] = useState(0);
  const [error, setError] = useState('');
  const [ccaCipher, setCcaCipher] = useState<{ c1: string; c2: string; p: string; m: string } | null>(null);
  const [ccaResult, setCcaResult] = useState<{ c1: string; c2: string; m: string; expected: string } | null>(null);

  const encrypt = async () => {
    setError('');
    setMalleated(null);
    setDecrypted('');
    try {
      const res = await fetch(`${API_BASE}/pa16/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ m: message }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setCipher({ c1: data.c1, c2: data.c2, p: data.p, m: data.m });
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const decrypt = async () => {
    if (!cipher) return;
    setError('');
    try {
      const res = await fetch(`${API_BASE}/pa16/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ c1: cipher.c1, c2: cipher.c2 }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setDecrypted(data.m);
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const malleate = async () => {
    if (!cipher) return;
    setError('');
    try {
      const res = await fetch(`${API_BASE}/pa16/malleate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ c1: cipher.c1, c2: cipher.c2, multiplier: 2 }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setMalleated({ c1: data.c1, c2: data.c2, m: data.m });
        const p = BigInt(cipher.p);
        const expected = (BigInt(cipher.m) * 2n) % p;
        const got = BigInt(data.m);
        setAttempts((prev) => prev + 1);
        if (expected === got) {
          setSuccessCount((prev) => prev + 1);
        }
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const encryptCCA = async () => {
    setError('');
    setCcaResult(null);
    try {
      const res = await fetch(`${API_BASE}/pa16/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ m: message }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setCcaCipher({ c1: data.c1, c2: data.c2, p: data.p, m: data.m });
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const submitOracle = async () => {
    if (!ccaCipher) return;
    setError('');
    try {
      const p = BigInt(ccaCipher.p);
      const c2 = (BigInt(ccaCipher.c2) * 2n) % p;
      const res = await fetch(`${API_BASE}/pa16/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ c1: ccaCipher.c1, c2: c2.toString() }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        const expected = (BigInt(ccaCipher.m) * 2n) % p;
        setCcaResult({
          c1: ccaCipher.c1,
          c2: c2.toString(),
          m: data.m,
          expected: expected.toString()
        });
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4">PA#16: ElGamal Malleability</h2>
        <p className="text-sm text-gray-600 mb-4">
          Encrypt a group element m, then multiply c2 by 2 to create a valid ciphertext for 2m.
        </p>

        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Message m (integer)</label>
            <input
              type="text"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
              value={message}
              onChange={(e) => setMessage(e.target.value.replace(/[^0-9]/g, ''))}
            />
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={encrypt}
            className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded"
          >
            Encrypt
          </button>
          <button
            onClick={decrypt}
            disabled={!cipher}
            className={`px-4 py-2 font-bold text-white rounded ${
              !cipher ? 'bg-gray-300 cursor-not-allowed' : 'bg-gray-700 hover:bg-gray-800'
            }`}
          >
            Decrypt
          </button>
          <button
            onClick={malleate}
            disabled={!cipher}
            className={`px-4 py-2 font-bold text-white rounded ${
              !cipher ? 'bg-green-300 cursor-not-allowed' : 'bg-green-600 hover:bg-green-700'
            }`}
          >
            Multiply c2 by 2
          </button>
        </div>
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-xl font-bold mb-4">Ciphertext</h3>
        {cipher ? (
          <div className="space-y-2">
            <div className="font-mono text-sm break-all">c1 = {cipher.c1}</div>
            <div className="font-mono text-sm break-all">c2 = {cipher.c2}</div>
            <div className="text-xs text-gray-500">p = {cipher.p}</div>
            <div className="text-xs text-gray-500">m = {cipher.m}</div>
          </div>
        ) : (
          <div className="text-sm text-gray-500">No ciphertext yet.</div>
        )}
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-xl font-bold mb-4">Malleability Result</h3>
        {malleated ? (
          <div className="space-y-2">
            <div className="font-mono text-sm break-all">c1 = {malleated.c1}</div>
            <div className="font-mono text-sm break-all">c2' = {malleated.c2}</div>
            <div className="font-mono text-sm break-all">Dec(c1, c2') = {malleated.m}</div>
          </div>
        ) : (
          <div className="text-sm text-gray-500">No malleated ciphertext yet.</div>
        )}
        <div className="mt-4 text-sm text-gray-600">
          Success counter: {successCount}/{attempts}
        </div>
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-xl font-bold mb-4">CCA Demonstration</h3>
        <p className="text-sm text-gray-600 mb-4">
          Encrypt a challenge, submit the modified ciphertext to the decryption oracle, and observe that
          the decrypted result is 2m. This shows ElGamal fails CCA.
        </p>

        <div className="flex flex-wrap gap-3 mb-4">
          <button
            onClick={encryptCCA}
            className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded"
          >
            Encrypt Challenge
          </button>
          <button
            onClick={submitOracle}
            disabled={!ccaCipher}
            className={`px-4 py-2 font-bold text-white rounded ${
              !ccaCipher ? 'bg-gray-300 cursor-not-allowed' : 'bg-orange-600 hover:bg-orange-700'
            }`}
          >
            Submit Modified Ciphertext
          </button>
        </div>

        {ccaCipher && (
          <div className="space-y-2">
            <div className="font-mono text-sm break-all">Challenge c1 = {ccaCipher.c1}</div>
            <div className="font-mono text-sm break-all">Challenge c2 = {ccaCipher.c2}</div>
            <div className="text-xs text-gray-500">m = {ccaCipher.m}</div>
          </div>
        )}

        {ccaResult && (
          <div className="mt-4 p-4 bg-gray-50 border border-gray-200 rounded">
            <div className="font-mono text-sm break-all">Modified c2' = {ccaResult.c2}</div>
            <div className="text-sm text-gray-700">Oracle output = {ccaResult.m}</div>
            <div className="text-xs text-gray-500">Expected 2m = {ccaResult.expected}</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PA16Demo;
