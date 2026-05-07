import { Link } from 'react-router-dom';

const Dashboard = () => {
  const assignments = [
    { title: 'PA#0: Base Explorer', link: '/explorer', description: 'The core visualization tool for tracing cryptographic reductions.', bg: 'bg-indigo-100', text: 'text-indigo-800' },
    { title: 'PA#1: PRG Interactive Demo', link: '/pa1', description: 'Live PRG output viewer with output length slider and randomness testing.', bg: 'bg-cyan-100', text: 'text-cyan-800' },
    { title: 'PA#3: IND-CPA Game', link: '/pa3', description: 'Play the IND-CPA game and track advantage with and without nonce reuse.', bg: 'bg-emerald-100', text: 'text-emerald-800' },
    { title: 'PA#5: MAC Forgery Game', link: '/pa5', description: 'MAC Forgery Game and length extension attack and PRF vs MAC.', bg: 'bg-yellow-100', text: 'text-yellow-800' },
    // More to be added by teammates later
    { title: 'PA#2: GGM Tree Visualiser', link: '/pa2', description: 'Explore the GGM binary tree construct for building PRFs from a PRG.', bg: 'bg-blue-100', text: 'text-blue-800' },
    { title: 'PA#8: DLP Hash Live', link: '/dlp', description: 'Compute DLP Hashes and run the Birthday Attack to solve the Discrete Logarithm.', bg: 'bg-purple-100', text: 'text-purple-800' },
    { title: 'PA#7: Merkle-Damgård Chain Viewer', link: '/md', description: 'Visualize the Merkle-Damgård transform and avalanche effect with editable blocks.', bg: 'bg-green-100', text: 'text-green-800' },
    { title: 'PA#14: RSA Broadcast Attack', link: '/rsa', description: 'Demo Håstad\'s Broadcast attack breaking textbook RSA and how PKCS#1 v1.5 defeats it.', bg: 'bg-red-100', text: 'text-red-800' },
    { title: 'PA#15: RSA Sign/Verify', link: '/pa15', description: 'Sign, verify, tamper, and see raw RSA multiplicative forgery.', bg: 'bg-rose-100', text: 'text-rose-800' },
    { title: 'PA#16: ElGamal Malleability', link: '/pa16', description: 'Multiply c2 to get 2m and see why ElGamal fails CCA.', bg: 'bg-teal-100', text: 'text-teal-800' },
    { title: 'PA#17: CCA Malleability Blocked', link: '/pa17', description: 'Encrypt-then-Sign blocks tampering, contrasted with plain ElGamal.', bg: 'bg-sky-100', text: 'text-sky-800' },
    { title: 'PA#19: Secure AND', link: '/pa19', description: 'Securely compute an AND gate using Oblivious Transfer step-by-step.', bg: 'bg-yellow-100', text: 'text-yellow-800' },
  ];

  return (
    <div className="bg-white shadow overflow-hidden sm:rounded-lg">
      <div className="px-4 py-5 sm:px-6 border-b border-gray-200">
        <h3 className="text-lg leading-6 font-medium text-gray-900">Assignment Dashboard</h3>
        <p className="mt-1 max-w-2xl text-sm text-gray-500">Pick an assignment demo to explore.</p>
      </div>
      <div className="p-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {assignments.map((item, index) => (
            <Link key={index} to={item.link} className={`rounded-xl p-6 shadow-sm ring-1 ring-black ring-opacity-5 hover:shadow-md transition duration-150 ease-in-out ${item.bg}`}>
              <h4 className={`text-xl font-bold ${item.text}`}>{item.title}</h4>
              <p className="mt-2 text-sm text-gray-700">{item.description}</p>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;