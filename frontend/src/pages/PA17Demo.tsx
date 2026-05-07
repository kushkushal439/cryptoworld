import { useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

const PA17Demo = () => {
  const [message, setMessage] = useState('42');
  const [ccaCipher, setCcaCipher] = useState<any>(null);
  const [ccaResult, setCcaResult] = useState<any>(null);
  const [elgCipher, setElgCipher] = useState<any>(null);
  const [elgResult, setElgResult] = useState<any>(null);
  const [successCount, setSuccessCount] = useState(0);
  const [attempts, setAttempts] = useState(0);
  const [error, setError] = useState('');

  const encryptCCA = async () => {
    setError('');
    setCcaResult(null);
    try {
      const res = await fetch(`${API_BASE}/pa17/cca_encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ m: message }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setCcaCipher(data);
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const decryptCCA = async (tamper: boolean) => {
    if (!ccaCipher) return;
    setError('');
    const c1 = ccaCipher.c1;
    const c2 = tamper ? (BigInt(ccaCipher.c2) + 1n).toString() : ccaCipher.c2;
    try {
      const res = await fetch(`${API_BASE}/pa17/cca_decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ c1, c2, sigma: ccaCipher.sigma }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setCcaResult({ ...data, tampered: tamper });
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const encryptElgamal = async () => {
    setError('');
    setElgResult(null);
    try {
      const res = await fetch(`${API_BASE}/pa17/elgamal_encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ m: message }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setElgCipher(data);
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const tamperElgamal = async () => {
    if (!elgCipher) return;
    setError('');
    const c1 = elgCipher.c1;
    const p = BigInt(elgCipher.p);
    const c2 = (BigInt(elgCipher.c2) * 2n) % p;

    try {
      const res = await fetch(`${API_BASE}/pa17/elgamal_decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ c1, c2: c2.toString() }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setAttempts((prev) => prev + 1);
        const expected = (BigInt(elgCipher.m) * 2n) % p;
        if (expected === BigInt(data.m)) {
          setSuccessCount((prev) => prev + 1);
        }
        setElgResult({ c1, c2: c2.toString(), m: data.m, expected: expected.toString() });
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
        <h2 className="text-2xl font-bold mb-4">PA#17: CCA Malleability Blocked</h2>
        <p className="text-sm text-gray-600 mb-4">
          Encrypt-then-Sign blocks tampering. Plain ElGamal still malleates to 2m.
        </p>

        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Message (integer)</label>
            <input
              type="text"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
              value={message}
              onChange={(e) => setMessage(e.target.value.replace(/[^0-9]/g, ''))}
            />
          </div>
        </div>
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-xl font-bold mb-4">Encrypt-then-Sign (CCA-Secure)</h3>
        <div className="flex flex-wrap gap-3 mb-4">
          <button
            onClick={encryptCCA}
            className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded"
          >
            Encrypt
          </button>
          <button
            onClick={() => decryptCCA(false)}
            disabled={!ccaCipher}
            className={`px-4 py-2 font-bold text-white rounded ${
              !ccaCipher ? 'bg-gray-300 cursor-not-allowed' : 'bg-gray-700 hover:bg-gray-800'
            }`}
          >
            Submit to Decrypt (untampered)
          </button>
          <button
            onClick={() => decryptCCA(true)}
            disabled={!ccaCipher}
            className={`px-4 py-2 font-bold text-white rounded ${
              !ccaCipher ? 'bg-orange-300 cursor-not-allowed' : 'bg-orange-600 hover:bg-orange-700'
            }`}
          >
            Tamper with CE
          </button>
        </div>

        {ccaCipher && (
          <div className="space-y-2">
            <div className="font-mono text-sm break-all">c1 = {ccaCipher.c1}</div>
            <div className="font-mono text-sm break-all">c2 = {ccaCipher.c2}</div>
            <div className="font-mono text-sm break-all">sigma = {ccaCipher.sigma}</div>
          </div>
        )}

        {ccaResult && (
          <div className="mt-4 p-4 bg-gray-50 border border-gray-200 rounded">
            <div className="text-xs uppercase text-gray-600 font-bold">Signature check</div>
            <div className="font-mono text-sm break-all">sigma^e mod N = {ccaResult.sigma_e}</div>
            <div className="font-mono text-sm break-all">H(CE) = {ccaResult.expected}</div>
            <div className={`mt-2 font-bold ${ccaResult.valid ? 'text-green-600' : 'text-red-600'}`}>
              {ccaResult.valid ? 'Signature valid' : 'Signature invalid'}
            </div>
            <div className="mt-1 text-sm text-gray-700">
              {ccaResult.valid ? `Decryption output: ${ccaResult.m}` : 'Decryption aborted, output ?'}
            </div>
          </div>
        )}
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-xl font-bold mb-4">Plain ElGamal (CCA-Insecure)</h3>
        <div className="flex flex-wrap gap-3 mb-4">
          <button
            onClick={encryptElgamal}
            className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded"
          >
            Encrypt
          </button>
          <button
            onClick={tamperElgamal}
            disabled={!elgCipher}
            className={`px-4 py-2 font-bold text-white rounded ${
              !elgCipher ? 'bg-green-300 cursor-not-allowed' : 'bg-green-600 hover:bg-green-700'
            }`}
          >
            Tamper (multiply c2 by 2)
          </button>
        </div>

        {elgCipher && (
          <div className="space-y-2">
            <div className="font-mono text-sm break-all">c1 = {elgCipher.c1}</div>
            <div className="font-mono text-sm break-all">c2 = {elgCipher.c2}</div>
            <div className="text-xs text-gray-500">m = {elgCipher.m}</div>
          </div>
        )}

        {elgResult && (
          <div className="mt-4 p-4 bg-gray-50 border border-gray-200 rounded">
            <div className="font-mono text-sm break-all">c2' = {elgResult.c2}</div>
            <div className="text-sm text-gray-700">Dec(c1, c2') = {elgResult.m}</div>
            <div className="text-xs text-gray-500">Expected 2m = {elgResult.expected}</div>
          </div>
        )}

        <div className="mt-4 text-sm text-gray-600">
          Success counter: {successCount}/{attempts}
        </div>
      </div>
    </div>
  );
};

export default PA17Demo;
