// frontend/src/pages/PA12Demo.tsx
import React, { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:5000/api';

interface EncryptionResult {
  c1: string;
  c2: string;
  padding1: string | null;
  padding2: string | null;
}

const PA12Demo: React.FC = () => {
  const [message, setMessage] = useState<string>('VOTE_YES');
  const [mode, setMode] = useState<'textbook' | 'pkcs15'>('textbook');
  const [encryptionResult, setEncryptionResult] = useState<EncryptionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [keyDetails, setKeyDetails] = useState<{ N: string, e: number, bits: number } | null>(null);

  useEffect(() => {
    // Fetch key details from the backend when the component mounts
    const fetchKeyDetails = async () => {
      try {
        const response = await fetch(`${API_BASE}/pa12/get-key-details`);
        if (!response.ok) throw new Error('Failed to fetch key details');
        const data = await response.json();
        setKeyDetails(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An unknown error occurred');
      }
    };
    fetchKeyDetails();
  }, []);

  const handleEncrypt = async () => {
    setError(null);
    setEncryptionResult(null);
    try {
      const response = await fetch(`${API_BASE}/pa12/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, mode }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Encryption failed');
      }
      setEncryptionResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
    }
  };

  const renderResultBanner = () => {
    if (!encryptionResult) return null;

    const areIdentical = encryptionResult.c1 === encryptionResult.c2;

    if (mode === 'textbook') {
      if (areIdentical) {
        return (
          <div className="p-4 mt-4 bg-red-900 border border-red-700 rounded-lg text-center">
            <h3 className="text-lg font-bold text-red-300">Identical Ciphertexts: Plaintext Leaked!</h3>
            <p className="text-red-400">An eavesdropper knows the same message was sent twice.</p>
          </div>
        );
      }
    } else if (mode === 'pkcs15') {
      if (!areIdentical) {
        return (
          <div className="p-4 mt-4 bg-green-900 border border-green-700 rounded-lg text-center">
            <h3 className="text-lg font-bold text-green-300">Different Ciphertexts: CPA-Secure!</h3>
            <p className="text-green-400">Random padding ensures encryptions of the same message are unique.</p>
          </div>
        );
      }
    }
    return null;
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 p-4">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4 text-gray-900">PA #12: Textbook RSA is Deterministic</h2>
        <p className="text-sm text-gray-600 mb-4">
          This demo shows why "textbook" RSA is insecure. Encrypting the same message always results in the same ciphertext, leaking information.
        </p>

        {keyDetails && (
          <div className="text-sm text-gray-500 mb-6 font-mono bg-gray-50 p-3 rounded">
            <p>Using {keyDetails.bits}-bit RSA Key | N = {keyDetails.N.substring(0, 40)}... | e = {keyDetails.e}</p>
          </div>
        )}

        <div className="flex flex-col gap-4 mb-4">
          <div className="w-full">
            <label htmlFor="message" className="block text-sm font-medium text-gray-700 mb-1">Message to Encrypt</label>
            <input
              id="message"
              type="text"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              className="block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
            />
          </div>
          
          <div className="flex items-center gap-6 mt-2">
             <div className="flex items-center gap-2">
                <input type="radio" id="textbook" name="mode" value="textbook" checked={mode === 'textbook'} onChange={() => setMode('textbook')} className="text-indigo-600 focus:ring-indigo-500 border-gray-300" />
                <label htmlFor="textbook" className="text-sm font-medium text-gray-700">Textbook RSA</label>
             </div>
             <div className="flex items-center gap-2">
                <input type="radio" id="pkcs15" name="mode" value="pkcs15" checked={mode === 'pkcs15'} onChange={() => setMode('pkcs15')} className="text-indigo-600 focus:ring-indigo-500 border-gray-300" />
                <label htmlFor="pkcs15" className="text-sm font-medium text-gray-700">PKCS#1 v1.5 RSA</label>
             </div>
          </div>

          <div className="mt-4">
            <button
              onClick={handleEncrypt}
              className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded"
            >
              Encrypt Twice
            </button>
          </div>
        </div>

        {error && <div className="p-4 mt-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}
      </div>

      {renderResultBanner()}

      {encryptionResult && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono">
          <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
            <h3 className="font-bold text-lg mb-4 text-gray-900 border-b pb-2">First Encryption</h3>
            <p className="text-sm break-all text-gray-800"><span className="font-bold text-indigo-700 block mb-1">Ciphertext (C1):</span> <span className="bg-gray-50 p-2 block rounded border border-gray-100">{encryptionResult.c1}</span></p>
            {encryptionResult.padding1 && <p className="text-sm mt-4 break-all text-gray-800"><span className="font-bold text-indigo-700 block mb-1">Padding (PS1):</span> <span className="bg-gray-50 p-2 block rounded border border-gray-100">{encryptionResult.padding1}</span></p>}
          </div>
          <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
            <h3 className="font-bold text-lg mb-4 text-gray-900 border-b pb-2">Second Encryption</h3>
            <p className="text-sm break-all text-gray-800"><span className="font-bold text-indigo-700 block mb-1">Ciphertext (C2):</span> <span className="bg-gray-50 p-2 block rounded border border-gray-100">{encryptionResult.c2}</span></p>
            {encryptionResult.padding2 && <p className="text-sm mt-4 break-all text-gray-800"><span className="font-bold text-indigo-700 block mb-1">Padding (PS2):</span> <span className="bg-gray-50 p-2 block rounded border border-gray-100">{encryptionResult.padding2}</span></p>}
          </div>
        </div>
      )}
    </div>
  );
};

export default PA12Demo;
