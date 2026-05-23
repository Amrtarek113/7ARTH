import React, { useState, useEffect } from 'react';
import { Box, Typography, useTheme, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper } from '@mui/material';
import { tokens } from '../../theme';
import axios from 'axios';
import Header from '../../components/Header';
import { useNavigate } from 'react-router-dom';
import AlertMessages from '../../components/alertMessages';

axios.defaults.baseURL = 'http://localhost:8080';

// Error Boundary
class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null, errorInfo: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Generic ErrorBoundary caught:', error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <Box sx={{ padding: '20px', color: 'red', backgroundColor: '#333' }}>
          <span>Error: {this.state.error?.message || 'Unknown error'}</span>
          <br />
          <span>Stack: {this.state.errorInfo?.componentStack || 'No stack trace'}</span>
        </Box>
      );
    }
    return this.props.children;
  }
}

const Generic = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  const navigate = useNavigate();
  const [metrics, setMetrics] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [error, setError] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));

  const fetchData = async () => {
    try {
      const storedToken = localStorage.getItem('token');
      if (!storedToken) {
        console.warn('No token found in localStorage');
        setError('Please log in to access the generic attacks data');
        navigate('/login');
        return;
      }

      console.log('Fetching /api/metrics...');
      const metricsResponse = await axios.get('/api/metrics', {
        headers: { Authorization: `Bearer ${storedToken}` },
      });
      console.log('Raw /api/metrics response:', JSON.stringify(metricsResponse, null, 2));
      if (metricsResponse.data.status === 'success' && metricsResponse.data.data) {
        setMetrics(metricsResponse.data.data);
        if (!metricsResponse.data.generic_attacks || metricsResponse.data.generic_attacks.current === 0) {
          console.warn('No Generic Attacks metrics returned. Check backend recent_incidents.');
        }
      } else {
        setError('Invalid metrics response. Check backend logs.');
        console.log('Invalid metrics response:', metricsResponse.data);
      }

      console.log('Fetching /api/recent-incidents?scenario=generic_attacks...');
      const incidentsResponse = await axios.get('/api/recent-incidents', {
        params: { scenario: 'generic_attacks', page: 1, per_page: 50 },
        headers: { Authorization: `Bearer ${storedToken}` },
      });
      console.log('Raw /api/recent-incidents response:', JSON.stringify(incidentsResponse, null, 2));
      console.log('Incident attack_cat values:', incidentsResponse.data?.data?.map(incident => incident.attack_cat));
      if (incidentsResponse.data.status === 'success' && Array.isArray(incidentsResponse.data.data)) {
        const genericIncidents = incidentsResponse.data.data.filter(incident => 
          incident.attack_cat === 'Generic'
        );
        console.log('Filtered Generic incidents:', JSON.stringify(genericIncidents, null, 2));
        setIncidents(genericIncidents.length > 0 ? genericIncidents : incidentsResponse.data.data);
        if (genericIncidents.length === 0) {
          console.warn('No Generic incidents found in generic_attacks scenario. Showing all generic_attacks incidents. Check backend attack_cat values for exact casing (expected: "Generic").');
        }
      } else {
        setError('Invalid incidents response. Check backend logs.');
        console.log('Invalid incidents response:', incidentsResponse.data);
      }

      setError(null);
    } catch (error) {
      console.error('Fetch error:', error);
      if (error.response) {
        console.error('Response error:', error.response.data, error.response.status);
        if (error.response.status === 401) {
          localStorage.removeItem('token');
          setToken(null);
          setError('Session expired. Please log in again.');
          navigate('/login');
        } else {
          setError(`API error: ${error.response.data?.message || error.response.statusText}`);
        }
      } else if (error.request) {
        setError('No response from backend. Ensure it’s running on port 8080.');
      } else {
        setError(`Error: ${error.message}`);
      }
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [navigate]);

  if (error) {
    return (
      <Box
        sx={{
          paddingLeft: "300px",
          boxSizing: "border-box",
          minHeight: "100vh",
          margin: "20px",
          textAlign: "center",
          color: colors.redAccent[500],
        }}
      >
        <Typography variant="h5">{error}</Typography>
      </Box>
    );
  }

  if (!metrics) {
    return (
      <Box
        sx={{
          paddingLeft: "300px",
          boxSizing: "border-box",
          minHeight: "100vh",
          margin: "20px",
          textAlign: "center",
          color: colors.grey[100],
        }}
      >
        <Typography variant="h5">Loading Generic Attacks data...</Typography>
      </Box>
    );
  }

  const genericAttacksData = metrics.generic_attacks || { current: 0 };

  return (
    <ErrorBoundary>
      <Box
        sx={{
          paddingLeft: "300px",
          boxSizing: "border-box",
          minHeight: "100vh",
          margin: "20px",
        }}
      >
        <Header title="GENERIC ATTACKS DETECTION" subtitle="Monitor Generic Attacks" />
        <Box mb="40px">
          <Box mb="20px">
            <Typography variant="h5" color={colors.grey[100]} fontWeight="600" mb="10px">
              Generic Attacks Statistics
            </Typography>
            <Typography variant="h6" color={colors.grey[100]}>
              Generic Attacks Incidents: {genericAttacksData.current || 0} occurrence(s)
            </Typography>
            {genericAttacksData.current === 0 && (
              <Typography variant="body1" color={colors.redAccent[500]}>
                Warning: No Generic incidents detected. Verify backend dataset contains attack_cat: Generic.
              </Typography>
            )}
          </Box>
          <Box>
            <Typography variant="h5" color={colors.grey[100]} fontWeight="600" mb="10px">
              Generic Attacks Incidents
            </Typography>
            {incidents.length > 0 ? (
              <TableContainer component={Paper} sx={{ backgroundColor: colors.primary[400] }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>Attack Category</TableCell>
                      <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>Date</TableCell>
                      <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>Confidence</TableCell>
                      <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>Prediction</TableCell>
                      <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>Threat</TableCell>
                      <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>Scenario</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {incidents.map((incident, i) => (
                      <TableRow key={`${incident.attack_cat || 'unknown'}-${i}`}>
                        <TableCell sx={{ color: colors.greenAccent[500] }}>
                          {incident.attack_cat || 'Unknown'}
                        </TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>
                          {incident.date || 'N/A'}
                        </TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>
                          {((incident.confidence || 0) * 100).toFixed(2)}%
                        </TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>
                          {incident.prediction || 'N/A'}
                        </TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>
                          {incident.threat || 'Unknown'}
                        </TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>
                          {incident.scenario || 'Unknown'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Typography color={colors.grey[100]}>
                No Generic incidents detected. Check backend data for scenario=generic_attacks and attack_cat: Generic.
              </Typography>
            )}
          </Box>
        </Box>
        <Box mt="20px">
          <AlertMessages token={token || 'mock-token'} />
        </Box>
      </Box>
    </ErrorBoundary>
  );
};

export default Generic;
