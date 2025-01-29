import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, useNavigate, useParams } from 'react-router-dom';
import './App.css';

const FilterSection = ({ filters, setFilters }) => {
  const years = Array.from({ length: 25 }, (_, i) => (new Date().getFullYear() - i).toString());
  const scores = Array.from({ length: 11 }, (_, i) => i.toFixed(1));
  const modifiedDays = [7, 30, 90, 180, 365];

  return (
    <div className="filterContainer" style={{ marginBottom: '20px', display: 'flex', gap: '20px', alignItems: 'center' }}>
      <div>
        <label>Year: </label>
        <select
          value={filters.year || ''}
          onChange={(e) => setFilters(prev => ({ ...prev, year: e.target.value }))}
          className="select"
        >
          <option value="">All Years</option>
          {years.map(year => (
            <option key={year} value={year}>{year}</option>
          ))}
        </select>
      </div>

      <div>
        <label>CVSS Score: </label>
        <select
          value={filters.score || ''}
          onChange={(e) => setFilters(prev => ({ ...prev, score: e.target.value }))}
          className="select"
        >
          <option value="">All Scores</option>
          {scores.map(score => (
            <option key={score} value={score}>{score}</option>
          ))}
        </select>
      </div>

      <div>
        <label>Modified Within: </label>
        <select
          value={filters.modifiedDays || ''}
          onChange={(e) => setFilters(prev => ({ ...prev, modifiedDays: e.target.value }))}
          className="select"
        >
          <option value="">Any Time</option>
          {modifiedDays.map(days => (
            <option key={days} value={days}>{days} days</option>
          ))}
        </select>
      </div>

      <button
        onClick={() => setFilters({})}
        className="clearButton"
        style={{
          padding: '5px 10px',
          backgroundColor: 'blue',
          border: '1px solid #ddd',
          borderRadius: '4px',
          cursor: 'pointer'
        }}
      >
        Clear Filters
      </button>
    </div>
  );
};

const CVEList = () => {
  const [cves, setCves] = useState([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [resultsPerPage, setResultsPerPage] = useState(10);
  const [hoveredRow, setHoveredRow] = useState(null);
  const [sortBy, setSortBy] = useState('published_date');
  const [sortOrder, setSortOrder] = useState('asc');
  const [filters, setFilters] = useState({});
  const navigate = useNavigate();

  useEffect(() => {
    fetchCVEs();
  }, [currentPage, resultsPerPage, sortBy, sortOrder, filters]);

  const fetchCVEs = async () => {
    try {
      const queryParams = new URLSearchParams({
        page: currentPage,
        per_page: resultsPerPage,
        sort_by: sortBy,
        sort_order: sortOrder,
        ...(filters.year && { year: filters.year }),
        ...(filters.score && { score: filters.score }),
        ...(filters.modifiedDays && { modified_days: filters.modifiedDays })
      });

      const response = await fetch(
        `http://localhost:5000/api/cves?${queryParams.toString()}`
      );
      const data = await response.json();
      setCves(data.results);
      setTotalRecords(data.total_records);
    } catch (error) {
      console.error('Error fetching CVEs:', error);
    }
  };

  return (
    <div className="container">
      <h1 className="header">CVE LIST</h1>

      <FilterSection filters={filters} setFilters={setFilters} />

      <div style={{ marginBottom: '20px' }}>
        <span style={{ fontWeight: '500' }}>Total Records: {totalRecords}</span>
      </div>

      {/* Sorting Controls */}
      <div className="sortContainer">
        <label>Sort By: </label>
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          className="select"
        >
          <option value="published_date">Published Date</option>
          <option value="last_modified_date">Last Modified Date</option>
        </select>

        <label>Sort Order: </label>
        <select
          value={sortOrder}
          onChange={(e) => setSortOrder(e.target.value)}
          className="select"
        >
          <option value="asc">Ascending</option>
          <option value="desc">Descending</option>
        </select>
      </div>

      <div className="tableContainer">
        <table className="table">
          <thead>
            <tr>
              <th className="th">CVE ID</th>
              <th className="th">IDENTIFIER</th>
              <th className="th">PUBLISHED DATE</th>
              <th className="th">LAST MODIFIED DATE</th>
              <th className="th">STATUS</th>
            </tr>
          </thead>
          <tbody>
            {cves.map((cve) => (
              <tr
                key={cve.cve_id}
                onClick={() => navigate(`/cves/${cve.cve_id}`)}
                onMouseEnter={() => setHoveredRow(cve.cve_id)}
                onMouseLeave={() => setHoveredRow(null)}
                className={hoveredRow === cve.cve_id ? 'trHover' : ''}
              >
                <td className="td">{cve.cve_id}</td>
                <td className="td">{cve.identifier}</td>
                <td className="td">{new Date(cve.published_date).toLocaleDateString()}</td>
                <td className="td">{new Date(cve.last_modified_date).toLocaleDateString()}</td>
                <td className="td">{cve.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="paginationContainer">
        <div>
          <label>Results per page: </label>
          <select
            value={resultsPerPage}
            onChange={(e) => {
              setResultsPerPage(Number(e.target.value));
              setCurrentPage(1);
            }}
            className="select"
          >
            <option value={10}>10</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </div>

        <div>
          <button
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className={`paginationButton ${currentPage === 1 ? 'disabledButton' : ''}`}
          >
            ◀
          </button>
          <span style={{ margin: '0 10px' }}>
            {(currentPage - 1) * resultsPerPage + 1} - {Math.min(currentPage * resultsPerPage, totalRecords)} of {totalRecords}
          </span>
          <button
            onClick={() => setCurrentPage((p) => p + 1)}
            disabled={currentPage * resultsPerPage >= totalRecords}
            className={`paginationButton ${currentPage * resultsPerPage >= totalRecords ? 'disabledButton' : ''}`}
          >
            ▶
          </button>
        </div>
      </div>
    </div>
  );
};

const CVEDetail = () => {
  const [cveData, setCveData] = useState(null);
  const { cveId } = useParams();

  useEffect(() => {
    const fetchCVEDetails = async () => {
      try {
        const response = await fetch(`http://localhost:5000/api/cves/${cveId}`);
        const data = await response.json();
        setCveData(data);
      } catch (error) {
        console.error('Error fetching CVE details:', error);
      }
    };

    fetchCVEDetails();
  }, [cveId]);

  if (!cveData) {
    return <div className="detailContainer">Loading...</div>;
  }

  return (
    <div className="detailContainer">
      <h1 className="detailHeader">{cveData.cve_id}</h1>

      <div className="section">
        <h2 className="sectionTitle">Description:</h2>
        <div className="content">{cveData.description}</div>
      </div>

      <div className="section">
        <h2 className="sectionTitle">CVSS V2 Metrics:</h2>
        <div className="content">
          <div className="label">Status:</div>{cveData.status}
          <div className="label">Score:</div>{cveData.cvss?.v2?.baseScore}
          <div className="label">Vector String:</div>{cveData.cvss?.v2?.vectorString}
        </div>
      </div>

      <div className="section">
        <h2 className="sectionTitle">CPE:</h2>
        <div className="content">
          <table className="table">
            <thead>
              <tr>
                <th className="th">Criteria</th>
                <th className="th">Match Criteria ID</th>
                <th className="th">Vulnerable</th>
              </tr>
            </thead>
            <tbody>
              {cveData.cpe?.map((cpe, index) => (
                <tr key={index}>
                  <td className="td">{cpe.criteria}</td>
                  <td className="td">{cpe.matchCriteriaId}</td>
                  <td className="td">{cpe.vulnerable ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/cves/list" element={<CVEList />} />
        <Route path="/cves/:cveId" element={<CVEDetail />} />
        <Route path="/" element={<CVEList />} />
      </Routes>
    </Router>
  );
};

export default App;
