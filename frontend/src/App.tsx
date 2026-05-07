import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Explorer from './pages/Explorer';
import MerkleDamgardDemo from './pages/MerkleDamgardDemo';
import DLPDemo from './pages/DLPDemo';
import RSADemo from './pages/RSADemo';
import PA19Demo from './pages/PA19Demo';
import PA2Demo from './pages/PA2Demo';
import PA1Demo from './pages/PA1Demo';
import PA3Demo from './pages/PA3Demo';
import PA15Demo from './pages/PA15Demo';
import PA16Demo from './pages/PA16Demo';
import PA17Demo from './pages/PA17Demo';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-100 flex flex-col">
        <nav className="bg-white shadow">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex h-16">
              <div className="flex">
                <div className="flex-shrink-0 flex items-center">
                  <Link to="/" className="text-xl font-bold text-gray-800">Minicrypt Web Explorer</Link>
                </div>
              </div>
            </div>
          </div>
        </nav>
        <main className="flex-1 w-full max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/explorer" element={<Explorer />} />
            <Route path="/md" element={<MerkleDamgardDemo />} />
            <Route path="/dlp" element={<DLPDemo />} />
            <Route path="/rsa" element={<RSADemo />} />
            <Route path="/pa1" element={<PA1Demo />} />
            <Route path="/pa3" element={<PA3Demo />} />
            <Route path="/pa15" element={<PA15Demo />} />
            <Route path="/pa16" element={<PA16Demo />} />
            <Route path="/pa17" element={<PA17Demo />} />
            <Route path="/pa19" element={<PA19Demo />} />
            <Route path="/pa2" element={<PA2Demo />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;

