import { useState, useEffect, useRef } from 'react';

const API_BASE = 'http://localhost:5000/api';

const PA2Demo = () => {
  const [key, setKey] = useState('00112233445566778899aabbccddeeff');
  const [query, setQuery] = useState('1010');
  const [isLoading, setIsLoading] = useState(false);
  const [treeData, setTreeData] = useState<any>(null);
  const [error, setError] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);

  const fetchTree = async () => {
    setIsLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/pa2/ggm_tree`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, query }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setTreeData(data);
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  // Re-fetch if key changes, but we also want instant highlight if query changes
  // Let's refetch on button click or query change.
  // Actually, we can fetch once for the tree, and dynamically highlight based on `query` state!
  
  const handleQueryChange = (e: any) => {
    // only allow 0s and 1s, max 8
    const val = e.target.value.replace(/[^01]/g, '').slice(0, 8);
    setQuery(val);
  };

  const handleKeyChange = (e: any) => {
    setKey(e.target.value);
  };

  useEffect(() => {
    if (scrollRef.current && treeData) {
      const container = scrollRef.current;
      container.scrollLeft = (container.scrollWidth - container.clientWidth) / 2;
    }
  }, [treeData]);

  // Optional: Auto fetch on mount or if key/depth changes significantly, but a button is fine.
  
  // Layout Constants for Proper Tree
  const nodeW = 110;
  const nodeH = 54;
  const gapY = 60;
  const padding = 40;

  let totalWidth = 1024;
  let totalHeight = 500;
  let nodesWithPos: any[] = [];
  
  if (treeData) {
    const leafCount = Math.pow(2, treeData.depth);
    totalWidth = Math.max(1024, leafCount * (nodeW + 10) + padding * 2);
    totalHeight = (treeData.depth + 1) * (nodeH + gapY) + padding * 2;
    
    nodesWithPos = treeData.nodes.map((node: any) => {
      const level = node.id.length;
      const index = node.id === '' ? 0 : parseInt(node.id, 2);
      const numNodesAtLevel = Math.pow(2, level);
      const regionWidth = (totalWidth - padding * 2) / numNodesAtLevel;
      const cx = padding + index * regionWidth + regionWidth / 2;
      const cy = padding + level * (nodeH + gapY) + nodeH / 2;
      return { ...node, cx, cy, level };
    });
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4">PA#2: GGM Tree Visualiser</h2>
        
        <p className="text-sm text-gray-600 mb-4">
          This visualises the Goldreich-Goldwasser-Micali (GGM) construction of a PRF from a length-doubling PRG. 
          By traversing the tree left (0) or right (1) according to the input query bits, we derive the resulting pseudorandom block.
        </p>

        {error && <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>}

        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Key (Hex)</label>
              <input
                type="text"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
                value={key}
                onChange={handleKeyChange}
                placeholder="e.g. 00112233..."
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Query x (Binary, length &le; 8)</label>
              <input
                type="text"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm tracking-widest"
                value={query}
                onChange={handleQueryChange}
                placeholder="1010"
              />
            </div>
          </div>
          
          <button
            onClick={fetchTree}
            disabled={isLoading}
            className={`px-4 py-2 font-bold text-white rounded ${isLoading ? 'bg-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'}`}
          >
            {isLoading ? 'Generating Tree...' : 'Generate Tree'}
          </button>
        </div>
      </div>

      {treeData && (
        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
          
          {/* Prominent output box */}
          <div className="mb-8 p-4 bg-indigo-50 border border-indigo-200 rounded-lg text-center shadow-sm">
            <h3 className="text-sm font-bold text-indigo-800 uppercase tracking-wider mb-2">Evaluated PRF Output</h3>
            <div className="text-xl md:text-2xl font-mono text-indigo-900 break-all">
              F_k(x) = {treeData.nodes.find((n: any) => n.id === query.substring(0, treeData.depth))?.value || "..."}
            </div>
          </div>

          {/* Tree Visualization */}
          <div ref={scrollRef} className="overflow-x-auto overflow-y-hidden pb-4 relative" style={{ height: totalHeight }}>
            <div className="absolute top-0 left-0" style={{ width: totalWidth, height: totalHeight }}>
              
              {/* Edges SVG */}
              <svg width={totalWidth} height={totalHeight} className="absolute top-0 left-0 pointer-events-none z-0">
                {nodesWithPos.filter(n => n.level > 0).map(node => {
                  const parentId = node.id.slice(0, -1);
                  const parent = nodesWithPos.find(n => n.id === parentId);
                  if (!parent) return null;
                  const isActiveEdge = query.startsWith(node.id);
                  return (
                    <line 
                      key={`edge-${node.id}`}
                      x1={parent.cx} y1={parent.cy + nodeH / 2} 
                      x2={node.cx} y2={node.cy - nodeH / 2} 
                      stroke={isActiveEdge ? "#3b82f6" : "#e5e7eb"} 
                      strokeWidth={isActiveEdge ? 3 : 1.5} 
                    />
                  );
                })}
              </svg>

              {/* Nodes */}
              {nodesWithPos.map((node: any) => {
                const isActive = query.startsWith(node.id);
                return (
                  <div
                    key={node.id}
                    style={{ left: node.cx - nodeW / 2, top: node.cy - nodeH / 2, width: nodeW, height: nodeH }}
                    className={`
                      absolute flex flex-col items-center justify-center p-1 md:p-2 rounded border text-[10px] z-10 font-mono
                      transition-colors duration-200
                      ${isActive ? 'bg-blue-100 border-blue-500 text-blue-900 shadow-md ring-2 ring-blue-300' : 'bg-white border-gray-300 text-gray-500 opacity-80'}
                    `}
                    title={`Path: ${node.id || 'Root'}`}
                  >
                    <div className="font-bold mb-1 border-b border-opacity-20 pb-1 w-full text-center text-xs space-x-1">
                      {node.id === '' ? 'Root' : node.id}
                    </div>
                    <div className="truncate w-full text-center" title={node.value}>
                      {node.value.substring(0, 6)}...{node.value.substring(node.value.length - 4)}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          
        </div>
      )}
    </div>
  );
};

export default PA2Demo;
