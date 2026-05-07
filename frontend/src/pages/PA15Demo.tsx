import { useMemo, useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

const PA15Demo = () => {
  const [message, setMessage] = useState('Hello CS8.401');
  const [rawMode, setRawMode] = useState(false);
  const [rawMessage, setRawMessage] = useState('12345');
  const [signature, setSignature] = useState('');
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [signMeta, setSignMeta] = useState<any>(null);
  const [error, setError] = useState('');
  const [tamperedMessage, setTamperedMessage] = useState<string | null>(null);

  const [m1, setM1] = useState('123');
  const [m2, setM2] = useState('456');
  const [forgeResult, setForgeResult] = useState<any>(null);

  const activeMessage = tamperedMessage ?? message;

  const canSign = useMemo(() => {
    if (rawMode) return rawMessage.trim().length > 0;
    return message.trim().length > 0;
  }, [rawMode, rawMessage, message]);

  const sign = async () => {
    setError('');
    setVerifyResult(null);
    setForgeResult(null);
    setTamperedMessage(null);

    try {
      const res = await fetch(`${API_BASE}/pa15/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rawMode ? { raw: true, m_int: rawMessage } : { message }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setSignature(data.signature);
        setSignMeta(data);
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const verify = async () => {
    if (!signature) return;
    setError('');
    try {
      const payload = rawMode
        ? { raw: true, m_int: rawMessage, signature }
        : { message: activeMessage, signature };
      const res = await fetch(`${API_BASE}/pa15/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setVerifyResult(data);
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const tamper = () => {
    if (rawMode) return;
    const encoder = new TextEncoder();
    const bytes = encoder.encode(message);
    if (bytes.length === 0) return;
    bytes[0] = bytes[0] ^ 0x01;
    const decoder = new TextDecoder();
    setTamperedMessage(decoder.decode(bytes));
    setVerifyResult(null);
  };

  const forge = async () => {
    setError('');
    try {
      const res = await fetch(`${API_BASE}/pa15/raw-forge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ m1, m2 }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setForgeResult(data);
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
        <h2 className="text-2xl font-bold mb-4">PA#15: RSA Sign and Verify</h2>
        <p className="text-sm text-gray-600 mb-4">
          Sign a message and verify the signature. Toggle raw RSA to see the multiplicative forgery.
        </p>

        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="flex items-center gap-3 mb-4">
          <label className="inline-flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={rawMode}
              onChange={(e) => {
                setRawMode(e.target.checked);
                setSignature('');
                setVerifyResult(null);
                setTamperedMessage(null);
              }}
              className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
            />
            Raw RSA sign (no hash)
          </label>
        </div>

        {!rawMode && (
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700">Message</label>
            <input
              type="text"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
              value={message}
              onChange={(e) => {
                setMessage(e.target.value);
                setTamperedMessage(null);
              }}
            />
            {tamperedMessage && (
              <div className="mt-2 text-xs text-orange-700">Tampered message: {tamperedMessage}</div>
            )}
          </div>
        )}

        {rawMode && (
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700">Message as integer</label>
            <input
              type="text"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
              value={rawMessage}
              onChange={(e) => setRawMessage(e.target.value.replace(/[^0-9]/g, ''))}
              placeholder="12345"
            />
          </div>
        )}

        <div className="flex flex-wrap gap-3">
          <button
            onClick={sign}
            disabled={!canSign}
            className={`px-4 py-2 font-bold text-white rounded ${
              !canSign ? 'bg-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'
            }`}
          >
            Sign
          </button>
          <button
            onClick={verify}
            disabled={!signature}
            className={`px-4 py-2 font-bold text-white rounded ${
              !signature ? 'bg-gray-300 cursor-not-allowed' : 'bg-gray-700 hover:bg-gray-800'
            }`}
          >
            Verify
          </button>
          <button
            onClick={tamper}
            disabled={rawMode || !signature}
            className={`px-4 py-2 font-bold text-white rounded ${
              rawMode || !signature ? 'bg-orange-300 cursor-not-allowed' : 'bg-orange-600 hover:bg-orange-700'
            }`}
          >
            Tamper
          </button>
        </div>
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-xl font-bold mb-4">Signature Output</h3>
        {signature ? (
          <div className="space-y-2">
            <div className="text-sm text-gray-600">Signature (hex)</div>
            <div className="font-mono text-sm text-gray-800 break-all bg-gray-50 border border-gray-200 p-3 rounded">
              {signature}
            </div>
            {signMeta && !rawMode && (
              <div className="text-xs text-gray-500">H(m) = {signMeta.hash_int}</div>
            )}
          </div>
        ) : (
          <div className="text-sm text-gray-500">No signature yet.</div>
        )}
      </div>

      {verifyResult && (
        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
          <h3 className="text-xl font-bold mb-4">Verification</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-gray-50 rounded border">
              <div className="text-xs uppercase text-gray-500 font-bold">Computed</div>
              <div className="font-mono text-sm break-all">sigma^e mod N = {verifyResult.sigma_e}</div>
            </div>
            <div className="p-4 bg-gray-50 rounded border">
              <div className="text-xs uppercase text-gray-500 font-bold">Expected</div>
              <div className="font-mono text-sm break-all">{verifyResult.expected}</div>
            </div>
          </div>
          <div className={`mt-4 font-bold ${verifyResult.valid ? 'text-green-600' : 'text-red-600'}`}>
            {verifyResult.valid ? 'Valid' : 'Invalid'}
          </div>
        </div>
      )}

      {rawMode && (
        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
          <h3 className="text-xl font-bold mb-4">Multiplicative Forgery (Raw RSA)</h3>
          <p className="text-sm text-gray-600 mb-4">
            Given signatures on m1 and m2, compute a valid signature on m1 * m2 without the private key.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">m1</label>
              <input
                type="text"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
                value={m1}
                onChange={(e) => setM1(e.target.value.replace(/[^0-9]/g, ''))}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">m2</label>
              <input
                type="text"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
                value={m2}
                onChange={(e) => setM2(e.target.value.replace(/[^0-9]/g, ''))}
              />
            </div>
          </div>
          <button
            onClick={forge}
            className="px-4 py-2 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded"
          >
            Demonstrate Forgery
          </button>

          {forgeResult && (
            <div className="mt-4 space-y-2">
              <div className="text-sm text-gray-600">m3 = (m1 * m2) mod N</div>
              <div className="font-mono text-sm break-all bg-gray-50 border border-gray-200 p-3 rounded">
                {forgeResult.m3}
              </div>
              <div className="text-sm text-gray-600">forged signature s3 = s1 * s2 mod N</div>
              <div className="font-mono text-sm break-all bg-gray-50 border border-gray-200 p-3 rounded">
                {forgeResult.s3}
              </div>
              <div className={`font-bold ${forgeResult.valid ? 'text-green-600' : 'text-red-600'}`}>
                {forgeResult.valid ? 'Forgery Verified' : 'Forgery Failed'}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default PA15Demo;
