// frontend/src/pages/PA4Demo.tsx

import React, { useState, useEffect } from 'react';
// import { ArrowRightIcon, XorIcon, LockClosedIcon, KeyIcon, RefreshIcon } from './Icons'; // Assuming you have an Icons file
import { Tab } from '@headlessui/react';


const API_BASE = 'http://localhost:5000/api'; // <-- ADD THIS LINE

// Helper to group array elements
const chunk = (arr: any[], size: number) =>
  Array.from({ length: Math.ceil(arr.length / size) }, (v, i) =>
    arr.slice(i * size, i * size + size)
  );

const BLOCK_SIZE = 32; // 16 bytes = 32 hex chars

const PA4Demo = () => {
  const [mode, setMode] = useState('CBC');
  const [plaintext, setPlaintext] = useState('A 3-block message for demo!');
  const [m1, setM1] = useState('First message.');
  const [m2, setM2] = useState('Second message.');
  const [reuseIv, setReuseIv] = useState(false);

  const [encryptionResult, setEncryptionResult] = useState<any>(null);
  const [bitFlipResult, setBitFlipResult] = useState<any>(null);
  const [ivReuseResult, setIvReuseResult] = useState<any>(null);
  
  const [animating, setAnimating] = useState(false);
  const [error, setError] = useState('');

  const handleEncrypt = async () => {
    setAnimating(true);
    setError('');
    setEncryptionResult(null);
    setBitFlipResult(null);
    setIvReuseResult(null);

    try {
      const response = await fetch(`${API_BASE}/pa4/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, plaintext }),
      });
      if (!response.ok) throw new Error('Encryption failed');
      const data = await response.json();
      setEncryptionResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setAnimating(false);
    }
  };

  const handleBitFlip = async (blockIndex: number) => {
    if (!encryptionResult) return;
    // For simplicity, we flip the first bit of the block
    const bitIndex = 0; 
    try {
      const response = await fetch(`${API_BASE}/pa4/flip-bit-and-decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode,
          ciphertext: encryptionResult.ciphertext,
          iv_or_nonce: encryptionResult.iv_or_nonce,
          block_index: blockIndex,
          bit_index: bitIndex,
        }),
      });
      if (!response.ok) throw new Error('Bit-flip failed');
      const data = await response.json();
      setBitFlipResult(data);
    } catch (err: any) {
      setError(err.message);
    }
  };
  
  const handleIvReuse = async () => {
    setAnimating(true);
    setError('');
    setEncryptionResult(null);
    setBitFlipResult(null);
    setIvReuseResult(null);
    
    try {
      const response = await fetch(`${API_BASE}/pa4/reuse-iv`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ m1, m2 }),
      });
      if (!response.ok) throw new Error('IV reuse demo failed');
      const data = await response.json();
      setIvReuseResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setAnimating(false);
    }
  };

  useEffect(() => {
    // Re-run encryption when mode changes, but not for IV reuse tab
    if (!reuseIv) {
      handleEncrypt();
    }
  }, [mode]);
  
  const getOriginalPlaintextBlocks = () => {
    if (!encryptionResult?.trace?.plaintext_blocks) return [];
    return encryptionResult.trace.plaintext_blocks;
  };

  const getCorruptedPlaintextBlocks = () => {
    if (!bitFlipResult?.corrupted_plaintext) return [];
    const hex = bitFlipResult.corrupted_plaintext;
    return chunk(hex.split(''), BLOCK_SIZE).map(c => c.join(''));
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4 text-gray-900">PA #4: Block Cipher Modes</h2>
      
      <Tab.Group onChange={(index) => setReuseIv(index === 3)}>
        <Tab.List className="flex space-x-1 rounded-xl bg-indigo-100 p-1 mb-4">
          {['CBC', 'OFB', 'CTR', 'IV Reuse Attack'].map((tabName) => (
            <Tab
              key={tabName}
              className={({ selected }) =>
                `w-full rounded-lg py-2.5 text-sm font-medium leading-5 text-indigo-700
                focus:outline-none focus:ring-2 
                ${selected ? 'bg-white shadow text-indigo-900' : 'hover:bg-white/[0.5]'}`
              }
              onClick={() => setMode(tabName === 'IV Reuse Attack' ? 'CBC' : tabName)}
            >
              {tabName}
            </Tab>
          ))}
        </Tab.List>
      </Tab.Group>

      {/* Main Content Area */}
      <div className="bg-white p-4 rounded-lg">
        {reuseIv ? (
          <IVReuseDemo m1={m1} setM1={setM1} m2={m2} setM2={setM2} onRun={handleIvReuse} result={ivReuseResult} />
        ) : (
          <EncryptionDemo
            mode={mode}
            plaintext={plaintext}
            setPlaintext={setPlaintext}
            onEncrypt={handleEncrypt}
            result={encryptionResult}
            onBitFlip={handleBitFlip}
            bitFlipResult={bitFlipResult}
            originalPlaintextBlocks={getOriginalPlaintextBlocks()}
            corruptedPlaintextBlocks={getCorruptedPlaintextBlocks()}
          />
        )}
        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}
      </div>
      </div>
    </div>
  );
};

// --- Sub-components for clarity ---

const EncryptionDemo = ({ mode, plaintext, setPlaintext, onEncrypt, result, onBitFlip, bitFlipResult, originalPlaintextBlocks, corruptedPlaintextBlocks }: any) => (
  <div>
    <div className="flex flex-wrap items-end gap-3 mb-4">
      <div className="flex-1">
        <label className="block text-sm font-medium text-gray-700 mb-1">Enter plaintext...</label>
        <input
          type="text"
          value={plaintext}
          onChange={(e) => setPlaintext(e.target.value)}
          className="block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
          placeholder="Enter plaintext..."
        />
      </div>
      <button onClick={onEncrypt} className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded h-11">
        Encrypt
      </button>
    </div>

    {result && (
      <div className="mt-6 bg-gray-50 border border-gray-200 rounded p-4">
        <h3 className="text-xl font-bold mb-4 text-gray-900">Encryption Result ({mode})</h3>
        <div className="space-y-2 font-mono text-sm text-gray-800">
          <p><span className="font-bold text-indigo-700">IV/Nonce:</span> {result.iv_or_nonce}</p>
          <p><span className="font-bold text-indigo-700">Ciphertext:</span></p>
          <div className="flex flex-wrap gap-2">
            {result.trace.ciphertext_blocks.map((block: string, i: number) => (
              <div key={i} className="relative group">
                <div className="bg-gray-200 border border-gray-300 p-2 rounded break-all">{block}</div>
                <button onClick={() => onBitFlip(i)} className="absolute -top-2 -right-2 bg-red-500 hover:bg-red-600 text-white rounded-full h-6 w-6 text-xs opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center font-sans shadow-md">
                  Flip
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    )}
    
    {bitFlipResult && (
      <div className="mt-6 bg-gray-50 border border-gray-200 rounded p-4">
        <h3 className="text-xl font-bold mb-4 text-gray-900">Bit Flip Decryption Result</h3>
        <p className="font-mono text-sm mb-2 text-gray-800"><span className="font-bold text-indigo-700">Flipped Ciphertext:</span> {bitFlipResult.flipped_ciphertext}</p>
        <p className="font-bold text-indigo-700 mb-2 font-mono text-sm">Corrupted Plaintext Blocks:</p>
        <div className="flex flex-wrap gap-2">
          {corruptedPlaintextBlocks.map((block: string, i: number) => {
            const originalBlock = originalPlaintextBlocks[i] || '';
            const isCorrupted = block !== originalBlock;
            return (
              <div key={i} className={`p-2 rounded font-mono text-sm break-all ${isCorrupted ? 'bg-red-100 border border-red-300 text-red-900' : 'bg-gray-200 border border-gray-300 text-gray-800'}`}>
                {block}
              </div>
            );
          })}
        </div>
        <p className="mt-4 font-mono text-sm text-gray-800"><span className="font-bold text-indigo-700">Decoded (ASCII):</span> {bitFlipResult.corrupted_plaintext_ascii}</p>
      </div>
    )}
  </div>
);

const IVReuseDemo = ({ m1, setM1, m2, setM2, onRun, result }: any) => {
  const highlightDiff = (c1: string, c2: string) => {
    const blocks1 = chunk(c1.split(''), BLOCK_SIZE).map(c => c.join(''));
    const blocks2 = chunk(c2.split(''), BLOCK_SIZE).map(c => c.join(''));
    
    return blocks1.map((block, i) => {
      const isMatch = block === blocks2[i];
      return (
        <div key={i} className={`p-2 rounded font-mono text-sm break-all border ${isMatch ? 'bg-red-100 border-red-300 text-red-900' : 'bg-gray-200 border-gray-300 text-gray-800'}`}>
          {block}
        </div>
      );
    });
  };

  return (
    <div>
      <h3 className="text-xl font-bold mb-4 text-gray-900">CBC IV Reuse Attack</h3>
      <p className="text-sm text-gray-600 mb-4">Encrypt two different messages with the same IV. If any plaintext blocks match, the corresponding ciphertext blocks will also match, leaking information.</p>
      <div className="space-y-4 mb-4">
        <div>
           <label className="block text-sm font-medium text-gray-700 mb-1">Message 1</label>
           <input type="text" value={m1} onChange={(e) => setM1(e.target.value)} className="block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm" />
        </div>
        <div>
           <label className="block text-sm font-medium text-gray-700 mb-1">Message 2</label>
           <input type="text" value={m2} onChange={(e) => setM2(e.target.value)} className="block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm" />
        </div>
      </div>
      <button onClick={onRun} className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded w-full">
        Run Attack
      </button>
      {result && (
        <div className="mt-6 bg-gray-50 border border-gray-200 rounded p-4 space-y-4 font-mono text-sm text-gray-800">
          <p><span className="font-bold text-indigo-700">Reused IV:</span> {result.iv}</p>
          <div>
            <p className="font-bold text-indigo-700 mb-1">Ciphertext 1 (C1):</p>
            <div className="flex flex-wrap gap-2">{highlightDiff(result.cbc.c1, result.cbc.c2)}</div>
          </div>
          <div>
            <p className="font-bold text-indigo-700 mb-1">Ciphertext 2 (C2):</p>
            <div className="flex flex-wrap gap-2">{highlightDiff(result.cbc.c2, result.cbc.c1)}</div>
          </div>
          <div className="mt-6 pt-4 border-t border-gray-300">
            <h3 className="text-lg font-bold mb-2 text-gray-900">OFB Keystream Reuse</h3>
            <p className="text-sm text-gray-600 mb-2 font-sans">In OFB, reusing an IV means reusing the keystream. C1 ⊕ C2 = M1 ⊕ M2.</p>
            <p><span className="font-bold text-indigo-700">Recovered M1 ⊕ M2:</span> {result.ofb.recovered_xor}</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default PA4Demo;