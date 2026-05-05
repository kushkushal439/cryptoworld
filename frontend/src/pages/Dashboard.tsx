import { Link } from 'react-router-dom';

const Dashboard = () => {
  const assignments = [
    { title: 'PA#0: Base Explorer', link: '/explorer', description: 'The core visualization tool for tracing cryptographic reductions.', bg: 'bg-indigo-100', text: 'text-indigo-800' },
    // More to be added by teammates later
    { title: 'PA#8: DLP Hash Live', link: '/dlp', description: 'Compute DLP Hashes and run the Birthday Attack to solve the Discrete Logarithm.', bg: 'bg-purple-100', text: 'text-purple-800' },
    { title: 'PA#7: Merkle-Damgård Chain Viewer', link: '/md', description: 'Visualize the Merkle-Damgård transform and avalanche effect with editable blocks.', bg: 'bg-green-100', text: 'text-green-800' },
    { title: 'PA#14: RSA Broadcast Attack', link: '/rsa', description: 'Demo Håstad\'s Broadcast attack breaking textbook RSA and how PKCS#1 v1.5 defeats it.', bg: 'bg-red-100', text: 'text-red-800' },
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