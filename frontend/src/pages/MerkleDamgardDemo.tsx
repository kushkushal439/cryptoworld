import { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:5000/api';

const MerkleDamgardDemo = () => {
  const [message, setMessage] = useState('');
  const [isHex, setIsHex] = useState(false);
  const [blocks, setBlocks] = useState<string[]>([]);
  const [chain, setChain] = useState<string[]>([]);
  const [error, setError] = useState('');

  const fetchPad = async () => {
    try {
      const res = await fetch(`${API_BASE}/md/pad`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, is_hex: isHex }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setBlocks(data.blocks);
        setError('');
      } else {
        setError(data.message);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const fetchChain = async (currentBlocks: string[]) => {
    if (currentBlocks.length === 0) {
      setChain([]);
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/md/chain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ blocks: currentBlocks, iv: '00000000' }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setChain(data.chain);
        setError('');
      } else {
        setError(data.message);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    fetchPad();
  }, [message, isHex]);

  useEffect(() => {
    fetchChain(blocks);
  }, [blocks]);

  const handleBlockChange = (index: number, newHex: string) => {
    const newBlocks = [...blocks];
    newBlocks[index] = newHex;
    setBlocks(newBlocks);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4">PA#7: Merkle-Damgård Chain Viewer</h2>
        
        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Input Message</label>
            <textarea
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2 font-mono"
              rows={3}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Enter text or hex..."
            />
          </div>
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              id="isHex"
              checked={isHex}
              onChange={(e) => setIsHex(e.target.checked)}
              className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
            />
            <label htmlFor="isHex" className="text-sm text-gray-700">Treat input as Hexadecimal</label>
          </div>
        </div>
      </div>

      {blocks.length > 0 && (
        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
          <h3 className="text-xl font-bold mb-4">MD Chain</h3>
          <div className="flex flex-col space-y-4">
            {/* IV Block */}
            <div className="flex items-center space-x-4">
              <div className="w-24 text-right font-bold text-gray-600">z_0 (IV)</div>
              <div className="p-3 bg-gray-100 rounded font-mono text-gray-700 border">
                00000000
              </div>
            </div>

            {blocks.map((block, index) => (
              <div key={index} className="flex items-center space-x-4">
                <div className="w-24 text-right">
                  <div className="font-bold text-gray-600">M_{index + 1}</div>
                </div>
                
                {/* Block Input */}
                <div className="flex-1">
                  <input
                    type="text"
                    value={block}
                    onChange={(e) => handleBlockChange(index, e.target.value)}
                    className="w-full font-mono p-2 border border-blue-300 rounded focus:ring-blue-500 focus:border-blue-500 bg-blue-50"
                  />
                  <div className="text-xs text-gray-500 mt-1">
                    {block.length / 2} bytes (Block Size: 8 bytes)
                  </div>
                </div>

                <div className="text-gray-400 font-bold px-2">{"-> h ->"}</div>

                {/* Next Chaining Value */}
                <div className="w-32 flex-shrink-0">
                  <div className="text-sm text-gray-500 mb-1">z_{index + 1}</div>
                  <div className="p-2 bg-green-100 text-green-800 font-mono rounded border border-green-300 text-center">
                    {chain[index + 1] || '...'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default MerkleDamgardDemo;
