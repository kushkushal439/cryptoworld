// frontend/src/pages/PA6Demo.tsx
import React, { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:5000/api';

interface EncryptPayload {
  r: string;
  c_E: string;
  t: string;
}

const PA6Demo: React.FC = () => {
  const [message, setMessage] = useState<string>('SEND_100_DOLLARS');
  const [encryptedData, setEncryptedData] = useState<EncryptPayload | null>(null);
  
  // Array of booleans representing the bits of c_E
  const [bits, setBits] = useState<boolean[]>([]);
  
  const [cpaResult, setCpaResult] = useState<string>('...');
  const [ccaResult, setCcaResult] = useState<string>('...');
  const [error, setError] = useState<string | null>(null);

  const hexToBits = (hex: string): boolean[] => {
    const bitArr: boolean[] = [];
    for (let i = 0; i < hex.length; i++) {
      const val = parseInt(hex[i], 16);
      for (let j = 3; j >= 0; j--) {
        bitArr.push((val & (1 << j)) !== 0);
      }
    }
    return bitArr;
  };

  const bitsToHex = (bitArr: boolean[]): string => {
    let hexStr = "";
    for (let i = 0; i < bitArr.length; i += 4) {
      let val = 0;
      for (let j = 0; j < 4; j++) {
        if (bitArr[i + j]) val |= (1 << (3 - j));
      }
      hexStr += val.toString(16);
    }
    return hexStr;
  };

  const handleEncrypt = async () => {
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/pa6/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Encryption failed');
      
      setEncryptedData(data);
      setBits(hexToBits(data.c_E));
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDecrypt = async (currentBits: boolean[]) => {
    if (!encryptedData) return;
    try {
      const modified_c_E = bitsToHex(currentBits);
      const response = await fetch(`${API_BASE}/pa6/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          r: encryptedData.r,
          c_E: modified_c_E,
          t: encryptedData.t
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Decryption failed');
      
      setCpaResult(data.cpa_result);
      setCcaResult(data.cca_result);
    } catch (err: any) {
      console.error(err);
    }
  };

  // Perform initial decryption whenever bits change
  useEffect(() => {
    if (bits.length > 0) {
      handleDecrypt(bits);
    }
  }, [bits]);

  const toggleBit = (idx: number) => {
    const newBits = [...bits];
    newBits[idx] = !newBits[idx];
    setBits(newBits);
  };

  // Split bits into byte (8-bit) groups for easier viewing
  const byteGroups = [];
  for (let i = 0; i < bits.length; i += 8) {
    byteGroups.push(bits.slice(i, i + 8));
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 p-4">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4 text-gray-900">PA #6: Malleability Attack vs CCA</h2>
        <p className="text-sm text-gray-600 mb-4">
          Encrypt a message to get a ciphertext C = (r, c_E) and a MAC tag t. 
          Click any bit in c_E to flip it. Observe how the CPA scheme blindly decrypts the tampered ciphertext, 
          giving a corrupted plaintext. Then observe how the CCA (Encrypt-then-MAC) scheme detects the tampering and rejects it with ⊥.
        </p>

        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="grid grid-cols-1 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Message to Encrypt</label>
            <div className="flex flex-wrap gap-3">
              <input
                type="text"
                className="flex-1 min-w-[200px] border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Type a message..."
              />
              <button
                onClick={handleEncrypt}
                className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded h-11"
              >
                Encrypt & Load
              </button>
            </div>
          </div>
        </div>
      </div>

      {encryptedData && (
        <div className="space-y-6">
          <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
            <h3 className="text-xl font-bold mb-4 text-gray-900">Ciphertext Bits (Click to Flip)</h3>
            <div className="flex flex-wrap gap-x-6 gap-y-4">
              {byteGroups.map((group, byteIdx) => (
                <div key={byteIdx} className="flex gap-1">
                  {group.map((bit, bitOffset) => {
                    const globalIdx = byteIdx * 8 + bitOffset;
                    return (
                      <button
                        key={globalIdx}
                        onClick={() => toggleBit(globalIdx)}
                        className={`w-8 h-8 flex items-center justify-center font-mono text-sm leading-none rounded transition-colors border shadow-sm
                          ${bit ? 'bg-indigo-100 border-indigo-300 text-indigo-900' : 'bg-gray-100 border-gray-300 text-gray-400'}
                          hover:bg-indigo-200 hover:text-indigo-900`}
                        title={`Bit ${globalIdx}`}
                      >
                        {bit ? '1' : '0'}
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
            
            <div className="mt-6 p-4 bg-gray-50 border border-gray-200 rounded font-mono text-sm break-all text-gray-800">
              <span className="font-bold text-indigo-700">Raw Hex c_E:</span> {bitsToHex(bits)}<br/>
              <span className="font-bold text-indigo-700 mt-2 block">MAC Tag t:</span> {encryptedData.t}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-white p-6 shadow-sm rounded-lg border border-red-200">
              <h3 className="text-xl font-bold mb-4 text-gray-900">CPA Decryption</h3>
              <p className="text-sm text-gray-600 mb-4 h-10">
                Blindly decrypts the ciphertext. Malleability allowed!
              </p>
              <div className="p-4 bg-red-50 border border-red-200 rounded text-red-900 font-mono min-h-[4rem] flex items-center shadow-inner">
                {cpaResult}
              </div>
            </div>

            <div className="bg-white p-6 shadow-sm rounded-lg border border-green-200">
              <h3 className="text-xl font-bold mb-4 text-gray-900">CCA Decryption</h3>
              <p className="text-sm text-gray-600 mb-4 h-10">
                Verifies the MAC first. Refuses to decrypt tampered ciphertexts.
              </p>
              <div className="p-4 bg-green-50 border border-green-200 rounded text-green-900 font-mono min-h-[4rem] flex items-center shadow-inner text-lg">
                {ccaResult.includes('⊥') ? (
                  <span className="text-red-700 font-bold animate-pulse inline-flex items-center gap-2">
                    <span>⛔</span> {ccaResult}
                  </span>
                ) : (
                  ccaResult
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PA6Demo;
