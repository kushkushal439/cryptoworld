import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { RefreshCw, Activity, ArrowRight } from 'lucide-react';

const PrimitiveOptions = ['OWF', 'PRG', 'PRF', 'OWP', 'PRP', 'MAC', 'CRHF', 'HMAC'];

const Explorer = () => {
    const [foundation, setFoundation] = useState('DLP (g^x mod p)');
    const [source, setSource] = useState('PRG');
    const [target, setTarget] = useState('PRF');
    const [inputA, setInputA] = useState('a3f2...');
    const [inputB, setInputB] = useState('1011');
    const [bidirectional] = useState(false);
    const [loading, setLoading] = useState(false);

    // Some dummy state to simulate API response data structure
    const [buildTrace, setBuildTrace] = useState<any[]>([]);
    const [reduceTrace, setReduceTrace] = useState<any[]>([]);
    const [fullChain, setFullChain] = useState<string[]>([]);

    // 1. Move fetchTraces OUTSIDE the useEffect so we can attach it to a button
    const fetchTraces = async () => {
        setLoading(true);
        try {
            const res = await axios.post('http://127.0.0.1:5000/api/reduce', {
                foundation,
                source,
                target,
                input: inputA,
                query: inputB
            });
            
            if(res.data) {
                setBuildTrace(res.data.build_trace || []);
                setReduceTrace(res.data.reduce_trace || []);
                setFullChain(res.data.full_chain || []);
            }
        } catch (err) {
            console.error('Failed to fetch from backend', err);
            setBuildTrace([{func: 'Error', val: 'Backend crashed or timed out.'}]);
        } finally {
            setLoading(false);
        }
    };

    // 2. Only auto-run when the dropdown menus change (NOT when typing)
    useEffect(() => {
        fetchTraces();
    }, [foundation, source, target, bidirectional]);


    return (
        <div className="bg-white border-2 border-gray-400 rounded-lg shadow-sm">
            {/* Top Bar: Foundation */}
            <div className="flex justify-between items-center bg-gray-200 border-b-2 border-gray-400 px-6 py-3 rounded-t-lg">
              <div className="flex space-x-4 items-center">
                  <span className="font-semibold text-gray-700">Foundation:</span>
                  <select 
                      className="border border-gray-400 bg-white rounded px-3 py-1 shadow-sm font-medium"
                      value={foundation}
                      onChange={(e) => setFoundation(e.target.value)}
                  >
                      <option value="DLP (g^x mod p)">DLP (g^x mod p)</option>
                      <option value="AES-128 (PRP)">AES-128 (PRP)</option>
                  </select>
              </div>
              <h2 className="text-gray-500 font-semibold tracking-wide">CS8.401 Minicrypt Clique Explorer</h2>
            </div>

            {/* Split Screen Columns */}
            <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x-2 divide-dashed divide-gray-400">
                {/* Column 1: Build Source */}
                <div className="bg-gray-50 p-6 flex flex-col space-y-6">
                    <h3 className="text-center font-semibold text-blue-700 bg-blue-100 py-2 border border-blue-300 rounded shadow-sm">Column 1: Build Source Primitive from Foundation</h3>
                    
                    <div className="border border-gray-400 bg-white p-6 rounded shadow-inner flex-1 flex flex-col items-center">
                        <div className="flex items-center space-x-2 mb-4 w-full justify-center">
                            <span className="text-sm font-medium text-gray-700">Source primitive A:</span>
                            <select 
                                value={source} onChange={(e) => setSource(e.target.value)}
                                className="border border-gray-300 rounded text-sm px-2 py-1 shadow-sm focus:ring-blue-500"
                            >
                                {PrimitiveOptions.map(p => <option key={`src-${p}`} value={p}>{p}</option>)}
                            </select>
                        </div>
                        <div className="flex items-center space-x-2 mb-8 w-full justify-center">
                            <span className="text-sm font-medium text-gray-700">Input seed:</span>
                            <input 
                                type="text" value={inputA} onChange={(e) => setInputA(e.target.value)} 
                                className="border border-gray-300 rounded text-sm px-2 py-1 shadow-sm"
                            />
                        </div>

                        {/* Rendering simulated Build trace */}
                        <div className="text-center space-y-3 font-mono text-sm border border-gray-100 p-4 w-full bg-gray-50 rounded">
                            {buildTrace.map((t, idx) => (
                                <div key={idx} className="text-gray-700">
                                    <span className="font-semibold">{t.func}:</span> {t.val}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Column 2: Reduce Source to Target */}
                <div className="bg-gray-50 p-6 flex flex-col space-y-6">
                    <h3 className="text-center font-semibold text-orange-700 bg-orange-100 py-2 border border-orange-300 rounded shadow-sm">Column 2: Reduce Source to Target Primitive</h3>
                    
                    <div className="border border-gray-400 bg-white p-6 rounded shadow-inner flex-1 flex flex-col items-center">
                        <div className="flex items-center space-x-2 mb-4 w-full justify-center">
                            <span className="text-sm font-medium text-gray-700">Target primitive B:</span>
                            <select 
                                value={target} onChange={(e) => setTarget(e.target.value)}
                                className="border border-gray-300 rounded text-sm px-2 py-1 shadow-sm focus:ring-orange-500"
                            >
                                {PrimitiveOptions.map(p => <option key={`tgt-${p}`} value={p}>{p}</option>)}
                            </select>
                        </div>
                        <div className="flex items-center space-x-2 mb-8 w-full justify-center">
                            <span className="text-sm font-medium text-gray-700">Query x:</span>
                            <input 
                                type="text" value={inputB} onChange={(e) => setInputB(e.target.value)} 
                                className="border border-gray-300 rounded text-sm px-2 py-1 shadow-sm"
                            />
                        </div>

                        {/* Rendering simulated Reduce trace */}
                        <div className="text-center space-y-3 font-mono text-sm border border-gray-100 p-4 w-full bg-gray-50 rounded">
                             {reduceTrace.map((t, idx) => (
                                <div key={idx} className="text-gray-700">
                                    <span className="font-semibold">{t.func}:</span> {t.val}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* Split Screen Columns */}
            <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x-2 divide-dashed divide-gray-400">
                {/* ... existing Column 1 and Column 2 code ... */}
            </div>

            {/* ADD THIS NEW COMPUTE BUTTON HERE */}
            <div className="bg-gray-200 border-t-2 border-b-2 border-gray-400 py-4 flex justify-center">
                <button 
                    onClick={fetchTraces}
                    disabled={loading}
                    className={`flex items-center space-x-2 px-8 py-2 rounded shadow-md font-bold text-white transition-colors ${loading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'}`}
                >
                    {loading ? <RefreshCw className="animate-spin" size={20} /> : <Activity size={20} />}
                    <span>{loading ? 'Computing Reduction...' : 'Run Cryptographic Reduction'}</span>
                </button>
            </div>

            {/* Proof Summary Bottom Panel */}
            <div className="border-t-2 border-gray-400 bg-yellow-50 p-6 rounded-b-lg flex flex-col items-center space-y-4">
                <h4 className="font-bold text-gray-800 tracking-wide text-sm flex items-center">
                    Reduction Chain Summary (click to expand)
                </h4>
                
                {/* Visual reduction string matching the spec image */}
                <div className="flex items-center justify-center space-x-2 w-full font-mono text-sm mt-4 text-gray-800 flex-wrap">
                    {fullChain.map((step, idx) => (
                        <React.Fragment key={idx}>
                            <span>{step}</span>
                            {idx < fullChain.length - 1 && (
                                <>
                                    <ArrowRight size={14} className="text-gray-400 mx-2" />
                                    <span className="text-xs text-gray-500 italic mt-[-15px] -ml-8 mr-1">convert</span>
                                </>
                            )}
                        </React.Fragment>
                    ))}
                </div>
            </div>
            
        </div>
    )
};

export default Explorer;