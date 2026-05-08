// frontend/src/pages/PA18Demo.tsx
import React, { useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

interface LogEntry {
  source: 'Bob' | 'Alice' | 'System';
  message: string;
  data?: string;
  isError?: boolean;
}

const PA18Demo: React.FC = () => {
  const [choice, setChoice] = useState<number | null>(null);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [protocolState, setProtocolState] = useState<'idle' | 'keys_sent' | 'ciphers_received' | 'decrypted' | 'cheated'>('idle');
  const [revealedMessage, setRevealedMessage] = useState<string | null>(null);

  const addLog = (entry: LogEntry) => setLog(prev => [...prev, entry]);

  const handleChoose = async (b: number) => {
    setChoice(b);
    setLog([]);
    setRevealedMessage(null);
    setProtocolState('idle');

    addLog({ source: 'Bob', message: `Choosing to receive message m${b}.` });
    addLog({ source: 'Bob', message: 'Generating two RSA key pairs (pk0, sk0) and (pk1, sk1)...' });

    try {
      const response = await fetch(`${API_BASE}/pa18/receiver-step1`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ b }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);

      addLog({ source: 'Bob', message: `Keeping sk${b} secret. Destroying sk${1 - b}.` });
      addLog({ source: 'Bob', message: 'Sending public keys (pk0, pk1) to Alice.' });
      addLog({ source: 'Alice', message: 'Received public keys.', data: `pk0_N: ${data.pk0_N.substring(0,20)}..., pk1_N: ${data.pk1_N.substring(0,20)}...` });
      setProtocolState('keys_sent');
    } catch (err) {
      addLog({ source: 'System', message: err instanceof Error ? err.message : 'An unknown error occurred', isError: true });
    }
  };

  const handleSenderStep = async () => {
    addLog({ source: 'Alice', message: 'Encrypting m0 with pk0 and m1 with pk1...' });
    try {
      const response = await fetch(`${API_BASE}/pa18/sender-step`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);

      addLog({ source: 'Alice', message: 'Sending ciphertexts (c0, c1) to Bob.' });
      addLog({ source: 'Bob', message: 'Received ciphertexts.', data: `c0: ${data.c0.substring(0,20)}..., c1: ${data.c1.substring(0,20)}...` });
      setProtocolState('ciphers_received');
    } catch (err) {
      addLog({ source: 'System', message: err instanceof Error ? err.message : 'An unknown error occurred', isError: true });
    }
  };

  const handleReceiverStep2 = async () => {
    if (choice === null) return;
    addLog({ source: 'Bob', message: `Decrypting ciphertext c${choice} using secret key sk${choice}...` });
    try {
      const response = await fetch(`${API_BASE}/pa18/receiver-step2`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);

      addLog({ source: 'Bob', message: `Decryption successful! Revealed message: "${data.recovered_message}"` });
      setRevealedMessage(data.recovered_message);
      setProtocolState('decrypted');
    } catch (err) {
      addLog({ source: 'System', message: err instanceof Error ? err.message : 'An unknown error occurred', isError: true });
    }
  };

  const handleCheatAttempt = async () => {
    if (choice === null) return;
    const unchosen = 1 - choice;
    addLog({ source: 'Bob', message: `(Attempting to cheat) Decrypting c${unchosen} with sk${choice}...` });
    try {
      const response = await fetch(`${API_BASE}/pa18/cheat-attempt`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);
      
      addLog({ source: 'System', message: data.message, isError: !data.success });
      setProtocolState('cheated');
    } catch (err) {
      addLog({ source: 'System', message: err instanceof Error ? err.message : 'An unknown error occurred', isError: true });
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 p-4">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h1 className="text-2xl font-bold mb-4 text-gray-900">PA #18: 1-out-of-2 Oblivious Transfer</h1>
        <p className="text-sm text-gray-600 mb-4">
          Play the role of Bob, the receiver. Choose one of Alice's two secret messages to receive, without her knowing which you chose, and without you learning the other message.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Alice's Panel */}
        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200 opacity-75">
          <h2 className="font-bold text-lg mb-4 text-gray-900 border-b pb-2">Alice's Panel (Sender)</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Message 0 (m0)</label>
              <div className="bg-gray-50 p-2 block rounded border border-gray-100 font-mono text-sm text-gray-400">??????????????????????????</div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Message 1 (m1)</label>
              <div className="bg-gray-50 p-2 block rounded border border-gray-100 font-mono text-sm text-gray-400">??????????????????????????</div>
            </div>
            <button onClick={handleSenderStep} disabled={protocolState !== 'keys_sent'} className="px-4 py-2 mt-4 w-full font-bold text-white bg-gray-500 hover:bg-gray-600 rounded disabled:opacity-50">
              Run Sender Step
            </button>
          </div>
        </div>

        {/* Bob's Panel */}
        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
          <h2 className="font-bold text-lg mb-4 text-gray-900 border-b pb-2">Bob's Panel (Receiver)</h2>
          <div className="space-y-4">
            <p className="text-sm text-gray-600">1. Choose which message you want to receive:</p>
            <div className="flex gap-4">
              <button onClick={() => handleChoose(0)} disabled={protocolState !== 'idle'} className="px-4 py-2 w-full font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded disabled:opacity-50">
                Choose m0
              </button>
              <button onClick={() => handleChoose(1)} disabled={protocolState !== 'idle'} className="px-4 py-2 w-full font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded disabled:opacity-50">
                Choose m1
              </button>
            </div>
            
            <p className="text-sm text-gray-600 mt-4">2. Decrypt your chosen message:</p>
            <button onClick={handleReceiverStep2} disabled={protocolState !== 'ciphers_received'} className="px-4 py-2 w-full font-bold text-white bg-green-600 hover:bg-green-700 rounded disabled:opacity-50">
              Decrypt Chosen Message
            </button>
            
            <div className="mt-4 p-4 bg-gray-50 rounded border border-gray-100 min-h-[6rem]">
              <h3 className="block text-sm font-medium text-gray-700 mb-1">Revealed Message:</h3>
              <p className="font-mono text-lg font-bold text-indigo-700 break-all">{revealedMessage ?? '???'}</p>
            </div>
            
            <button onClick={handleCheatAttempt} disabled={protocolState !== 'decrypted'} className="px-4 py-2 mt-2 w-full font-bold text-white bg-red-600 hover:bg-red-700 rounded disabled:opacity-50">
              Attempt to Cheat (Decrypt Other)
            </button>
          </div>
        </div>
      </div>

      {/* Log Panel */}
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200 mt-6">
        <h2 className="font-bold text-lg mb-4 text-gray-900 border-b pb-2">Protocol Log</h2>
        <div className="h-64 overflow-y-auto bg-gray-50 p-3 rounded border border-gray-200 font-mono text-sm space-y-2">
          {log.map((entry, i) => (
            <div key={i} className={`pb-1 ${entry.isError ? 'text-red-700 bg-red-50 p-2 rounded border border-red-100' : 'text-gray-800 border-b border-gray-100 last:border-0'}`}>
              <span className={`font-bold ${entry.source === 'Bob' ? 'text-indigo-600' : entry.source === 'Alice' ? 'text-teal-600' : 'text-gray-600'}`}>
                {entry.source}:
              </span> {entry.message}
              {entry.data && <span className="block pl-6 pt-1 text-xs text-gray-500 break-all">{entry.data}</span>}
            </div>
          ))}
          {log.length === 0 && <p className="text-gray-400 italic">No activity yet. Start the protocol by making a choice.</p>}
        </div>
      </div>
    </div>
  );
};

export default PA18Demo;