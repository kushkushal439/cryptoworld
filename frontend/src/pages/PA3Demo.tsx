import { useMemo, useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

type ChallengeResponse = {
  challenge_id: string;
  ciphertext: { r: string; c: string };
  oracle?: { r: string; c: string };
  reuse_nonce: boolean;
};

const PA3Demo = () => {
  const [m0, setM0] = useState('Attack at dawn!');
  const [m1, setM1] = useState('Attack at dusk!');
  const [reuseNonce, setReuseNonce] = useState(false);
  const [challenge, setChallenge] = useState<ChallengeResponse | null>(null);
  const [error, setError] = useState('');
  const [rounds, setRounds] = useState(0);
  const [correctCount, setCorrectCount] = useState(0);
  const [lastResult, setLastResult] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const equalLength = m0.length === m1.length && m0.length > 0;

  const advantage = useMemo(() => {
    if (rounds === 0) return 0;
    return Math.abs((2 * correctCount) / rounds - 1);
  }, [rounds, correctCount]);

  const requestChallenge = async () => {
    setIsLoading(true);
    setError('');
    setLastResult(null);
    try {
      const res = await fetch(`${API_BASE}/pa3/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ m0, m1, reuse_nonce: reuseNonce }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setChallenge(data as ChallengeResponse);
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const submitGuess = async (guess: number) => {
    if (!challenge) return;
    setIsLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/pa3/guess`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge_id: challenge.challenge_id, guess }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        const newRounds = rounds + 1;
        const newCorrect = correctCount + (data.correct ? 1 : 0);
        setRounds(newRounds);
        setCorrectCount(newCorrect);
        setLastResult(data.correct ? 'Correct' : `Wrong (b = ${data.actual_b})`);
        setChallenge(null);
      } else {
        setError(data.message || 'Unknown error');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const resetStats = () => {
    setRounds(0);
    setCorrectCount(0);
    setLastResult(null);
    setChallenge(null);
    setError('');
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h2 className="text-2xl font-bold mb-4">PA#3: IND-CPA Game</h2>
        <p className="text-sm text-gray-600 mb-4">
          Act as the adversary. Provide two equal-length messages, encrypt one at random, and try to guess the bit.
          The advantage should converge to ~0 in secure mode, and to 1 with nonce reuse.
        </p>

        {error && (
          <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg">{error}</div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Message m0</label>
            <input
              type="text"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
              value={m0}
              onChange={(e) => setM0(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Message m1</label>
            <input
              type="text"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-3 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
              value={m1}
              onChange={(e) => setM1(e.target.value)}
            />
          </div>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center gap-4 mb-4">
          <label className="inline-flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={reuseNonce}
              onChange={(e) => setReuseNonce(e.target.checked)}
              className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
            />
            Reuse nonce (broken)
          </label>

          <div className="text-xs text-gray-500">
            {equalLength ? `Length = ${m0.length} bytes` : 'm0 and m1 must be equal length'}
          </div>
        </div>

        <div className="flex gap-3">
          <button
            onClick={requestChallenge}
            disabled={!equalLength || isLoading}
            className={`px-4 py-2 font-bold text-white rounded ${
              !equalLength || isLoading ? 'bg-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'
            }`}
          >
            {isLoading ? 'Encrypting...' : 'Encrypt'}
          </button>

          <button
            onClick={resetStats}
            className="px-4 py-2 font-bold text-white bg-gray-600 hover:bg-gray-700 rounded"
          >
            Reset Stats
          </button>
        </div>
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-xl font-bold mb-4">Challenge Output</h3>

        {!challenge && (
          <div className="text-sm text-gray-500">Click Encrypt to get a challenge ciphertext.</div>
        )}

        {challenge && (
          <div className="space-y-4">
            <div className="p-4 bg-indigo-50 border border-indigo-200 rounded">
              <div className="text-xs uppercase text-indigo-700 font-bold mb-2">Ciphertext (r || c)</div>
              <div className="font-mono text-sm text-indigo-900 break-all">
                r = {challenge.ciphertext.r}
              </div>
              <div className="font-mono text-sm text-indigo-900 break-all">
                c = {challenge.ciphertext.c}
              </div>
            </div>

            {challenge.reuse_nonce && challenge.oracle && (
              <div className="p-4 bg-yellow-50 border border-yellow-200 rounded">
                <div className="text-xs uppercase text-yellow-700 font-bold mb-2">Oracle Encrypt(m0) with same nonce</div>
                <div className="font-mono text-sm text-yellow-900 break-all">
                  r = {challenge.oracle.r}
                </div>
                <div className="font-mono text-sm text-yellow-900 break-all">
                  c = {challenge.oracle.c}
                </div>
                <div className="mt-2 text-xs text-yellow-800">
                  If c* equals c0 then b = 0, otherwise b = 1. This forces advantage to 1.
                </div>
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={() => submitGuess(0)}
                disabled={isLoading}
                className="px-4 py-2 font-bold text-white bg-green-600 hover:bg-green-700 rounded"
              >
                Guess b = 0
              </button>
              <button
                onClick={() => submitGuess(1)}
                disabled={isLoading}
                className="px-4 py-2 font-bold text-white bg-blue-600 hover:bg-blue-700 rounded"
              >
                Guess b = 1
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="bg-white p-6 shadow-sm rounded-lg border border-gray-200">
        <h3 className="text-xl font-bold mb-4">Advantage Tracker</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-gray-50 border border-gray-200 rounded">
            <div className="text-xs uppercase text-gray-600 font-bold">Rounds</div>
            <div className="text-2xl font-bold text-gray-800">{rounds}</div>
          </div>
          <div className="p-4 bg-gray-50 border border-gray-200 rounded">
            <div className="text-xs uppercase text-gray-600 font-bold">Correct</div>
            <div className="text-2xl font-bold text-gray-800">{correctCount}</div>
          </div>
          <div className="p-4 bg-gray-50 border border-gray-200 rounded">
            <div className="text-xs uppercase text-gray-600 font-bold">Advantage</div>
            <div className="text-2xl font-bold text-gray-800">{advantage.toFixed(2)}</div>
          </div>
        </div>

        <div className="mt-4 text-sm text-gray-600">
          Target: after 20 rounds, advantage should be &le; 0.10 in secure mode, and 1.00 with nonce reuse.
        </div>

        {lastResult && (
          <div className="mt-4 text-sm font-semibold text-indigo-700">
            Last guess: {lastResult}
          </div>
        )}
      </div>
    </div>
  );
};

export default PA3Demo;
