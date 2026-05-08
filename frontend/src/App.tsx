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
import PA5Demo from './pages/PA5Demo';
import PA10Demo from './pages/PA10Demo';
import PA11Demo from './pages/PA11Demo';
import PA13Demo from './pages/PA13Demo';
import PA4Demo from './pages/PA4Demo';
import PA9Demo from './pages/PA9Demo';
import PA12Demo from './pages/PA12Demo';
import PA18Demo from './pages/PA18Demo';
import PA6Demo from './pages/PA6Demo';

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
            <Route path="/pa5" element={<PA5Demo />} />
            <Route path="/pa10" element={<PA10Demo />} />
            <Route path="/pa11" element={<PA11Demo />} />
            <Route path="/pa13" element={<PA13Demo />} />
            <Route path="/pa4" element={<PA4Demo />} />
            <Route path="/pa15" element={<PA15Demo />} />
            <Route path="/pa16" element={<PA16Demo />} />
            <Route path="/pa17" element={<PA17Demo />} />
            <Route path="/pa19" element={<PA19Demo />} />
            <Route path="/pa2" element={<PA2Demo />} />
            <Route path="/pa9" element={<PA9Demo />} />
            <Route path="/pa4" element={<PA4Demo />} />
            <Route path="/pa12" element={<PA12Demo />} />
            <Route path="/pa18" element={<PA18Demo />} />
            <Route path="/pa6" element={<PA6Demo />} />

          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;

