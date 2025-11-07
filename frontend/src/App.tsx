import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import QueryGenerator from './pages/QueryGenerator';
import HuntCampaigns from './pages/HuntCampaigns';
import Templates from './pages/Templates';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/query-generator" element={<QueryGenerator />} />
          <Route path="/campaigns" element={<HuntCampaigns />} />
          <Route path="/templates" element={<Templates />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
