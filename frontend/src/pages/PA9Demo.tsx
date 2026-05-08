// frontend/src/pages/PA9Demo.tsx
import React, { useState, useEffect, useRef } from 'react';
import { Chart, registerables } from 'chart.js';
import 'chart.js/auto';

Chart.register(...registerables);
const API_BASE = 'http://localhost:5000/api';

interface AttackStep {
  k: number;
  x: string;
  hx: number;
  status: 'hashing' | 'collision';
  collision_pair?: {
    x1: string;
    x2: string;
  };
}

const PA9Demo: React.FC = () => {
  const [bitLength, setBitLength] = useState<number>(12);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [attackLog, setAttackLog] = useState<AttackStep[]>([]);
  const [collisionInfo, setCollisionInfo] = useState<AttackStep | null>(null);
  
  const chartRef = useRef<HTMLCanvasElement>(null);
  const chartInstance = useRef<Chart | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (chartRef.current) {
      chartInstance.current = new Chart(chartRef.current, {
        type: 'line',
        data: {
          datasets: [
            {
              label: 'Theoretical Probability 1 - e^(-k²/2ⁿ)',
              data: [],
              borderColor: 'rgb(255, 99, 132)',
              borderDash: [5, 5],
              tension: 0.4,
              pointRadius: 0,
            },
            {
              label: 'Empirical Attack Progress',
              data: [],
              borderColor: 'rgb(75, 192, 192)',
              backgroundColor: 'rgba(75, 192, 192, 0.5)',
              showLine: false,
              pointRadius: 3,
            }
          ],
        },
        options: {
          scales: {
            x: {
              type: 'linear',
              title: { display: true, text: 'Hashes Computed (k)' },
              beginAtZero: true,
            },
            y: {
              title: { display: true, text: 'Collision Probability' },
              min: 0,
              max: 1.1,
            },
          },
          animation: { duration: 0 },
        },
      });
    }

    return () => {
      chartInstance.current?.destroy();
      eventSourceRef.current?.close();
    };
  }, []);

  const updateChart = (k: number, bitLen: number, isCollision: boolean) => {
    if (chartInstance.current) {
      const chart = chartInstance.current;
      const spaceSize = Math.pow(2, bitLen);
      
      // Calculate theoretical probability P(k) = 1 - exp(-k(k-1)/(2N))
      const prob = 1 - Math.exp(-(k * (k - 1)) / (2 * spaceSize));
      
      chart.data.datasets[0].data.push({ x: k, y: prob });
      
      // For the empirical progress, we just plot a point tracking the line
      // When a collision hits, we drop a distinct point
      chart.data.datasets[1].data.push({ x: k, y: isCollision ? 1 : prob });

      chart.update();
    }
  };

  const startAttack = () => {
    if (isRunning) {
      eventSourceRef.current?.close();
      setIsRunning(false);
      return;
    }

    setIsRunning(true);
    setAttackLog([]);
    setCollisionInfo(null);

    if (chartInstance.current) {
      chartInstance.current.data.datasets.forEach((dataset) => { dataset.data = []; });
      chartInstance.current.update();
    }

    const es = new EventSource(`${API_BASE}/pa9/start-birthday-attack/${bitLength}`);

    eventSourceRef.current = es;

    es.onmessage = (event) => {
      const parsedData = JSON.parse(event.data);
      console.log('Received event:', parsedData);

      if (parsedData.type === 'attack_step') {
        const step: AttackStep = parsedData.data;
        const isCollision = step.status === 'collision';
        
        setAttackLog(prev => [...prev.slice(-15), step]);
        updateChart(step.k, bitLength, isCollision);

        if (isCollision) {
          setCollisionInfo(step);
          setIsRunning(false);
          es.close();
        }
      }
    };

    es.onerror = () => {
      setIsRunning(false);
      es.close();
    };
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 p-4">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4 text-gray-900">PA #9: Live Birthday Attack</h2>
      
        <div className="flex flex-wrap items-end gap-6 mb-4">
          <div className="flex flex-col">
            <label className="block text-sm font-medium text-gray-700 mb-1">Output Bit Length (n)</label>
            <select 
              value={bitLength} 
              onChange={(e) => setBitLength(Number(e.target.value))}
              disabled={isRunning}
              className="block w-full border border-gray-300 rounded-md shadow-sm p-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
            >
              <option value="8">8 bits (Fast)</option>
              <option value="10">10 bits</option>
              <option value="12">12 bits</option>
              <option value="14">14 bits</option>
              <option value="16">16 bits (Slow)</option>
            </select>
          </div>
          <button
            onClick={startAttack}
            className={`px-4 py-2 font-bold text-white rounded h-[38px] ${isRunning ? 'bg-red-600 hover:bg-red-700' : 'bg-indigo-600 hover:bg-indigo-700'}`}
          >
            {isRunning ? 'Stop Attack' : 'Run Attack'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
          <h3 className="text-xl font-bold mb-4 text-gray-900">Collision Probability Curve</h3>
          <canvas ref={chartRef}></canvas>
        </div>

        <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
          <h3 className="text-xl font-bold mb-4 text-gray-900">Live Hash Feed</h3>
          <div className="h-64 overflow-y-auto bg-gray-50 border border-gray-200 p-4 rounded font-mono text-sm text-gray-800">
            {attackLog.map((s, i) => (
              <div key={i}>{`k=${s.k}: H(${s.x.substring(0,8)}...) = ${s.hx}`}</div>
            ))}
          </div>
        </div>
      </div>

      {collisionInfo && (
        <div className="mt-6 bg-green-50 border border-green-200 p-6 rounded-lg animate-pulse">
          <h3 className="text-2xl font-bold text-green-800 mb-4">Collision Found!</h3>
          <div className="font-mono mt-2 space-y-2 text-gray-800">
            <p><span className="font-bold text-green-900">Hashes Tried (k):</span> {collisionInfo.k}</p>
            <p><span className="font-bold text-green-900">Input 1 (x1):</span> {collisionInfo.collision_pair?.x1}</p>
            <p><span className="font-bold text-green-900">Input 2 (x2):</span> {collisionInfo.collision_pair?.x2}</p>
            <p><span className="font-bold text-green-900">Shared Hash H(x):</span> {collisionInfo.hx}</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default PA9Demo;