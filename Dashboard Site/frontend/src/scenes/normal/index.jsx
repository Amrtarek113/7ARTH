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
    console.error('Normal ErrorBoundary caught:', error, errorInfo);
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

const Normal = () => {
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
        setError('Please log in to access the normal traffic data');
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
        if (!metricsResponse.data.normal || metricsResponse.data.normal.current === 0) {
          console.warn('No Normal metrics returned. Check backend recent_incidents.');
        }
      } else {
        setError('Invalid metrics response. Check backend logs.');
        console.log('Invalid metrics response:', metricsResponse.data);
      }

      console.log('Fetching /api/recent-incidents?scenario=normal...');
      let incidentsResponse = await axios.get('/api/recent-incidents', {
        params: { scenario: 'normal', page: 1, per_page: 50 },
        headers: { Authorization: `Bearer ${storedToken}` },
      });
      console.log('Raw /api/recent-incidents response (scenario=normal):', JSON.stringify(incidentsResponse, null, 2));
      console.log('Incident attack_cat values:', incidentsResponse.data?.data?.map(incident => incident.attack_cat));

      let normalIncidents = [];
      if (incidentsResponse.data.status === 'success' && Array.isArray(incidentsResponse.data.data)) {
        normalIncidents = incidentsResponse.data.data.filter(incident => 
          incident.attack_cat === 'Normal'
        );
        console.log('Filtered Normal incidents (scenario=normal):', JSON.stringify(normalIncidents, null, 2));
      }

      if (normalIncidents.length === 0) {
        console.warn('No Normal incidents found in normal scenario. Fetching all incidents as fallback.');
        incidentsResponse = await axios.get('/api/recent-incidents', {
          params: { page: 1, per_page: 50 },
          headers: { Authorization: `Bearer ${storedToken}` },
        });
        console.log('Raw /api/recent-incidents response (no scenario):', JSON.stringify(incidentsResponse, null, 2));
        console.log('Incident attack_cat values (no scenario):', incidentsResponse.data?.data?.map(incident => incident.attack_cat));
        if (incidentsResponse.data.status === 'success' && Array.isArray(incidentsResponse.data.data)) {
          normalIncidents = incidentsResponse.data.data.filter(incident => 
            incident.attack_cat === 'Normal'
          );
          console.log('Filtered Normal incidents (no scenario):', JSON.stringify(normalIncidents, null, 2));
          setIncidents(normalIncidents.length > 0 ? normalIncidents : incidentsResponse.data.data);
          if (normalIncidents.length === 0) {
            console.warn('No Normal incidents found in fallback fetch. Showing all incidents. Check backend attack_cat values for exact casing (expected: "Normal").');
          }
        } else {
          setError('Invalid incidents response in fallback fetch. Check backend logs.');
          console.log('Invalid incidents response (no scenario):', incidentsResponse.data);
        }
      } else {
        setIncidents(normalIncidents);
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
        <Typography variant="h5">Loading Normal Traffic data...</Typography>
      </Box>
    );
  }

  const normalData = metrics.normal || { current: 0 };

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
        <Header title="NORMAL TRAFFIC DETECTION" subtitle="Monitor Normal Network Traffic" />
        <Box mb="40px">
          <Box mb="20px">
            <Typography variant="h5" color={colors.grey[100]} fontWeight="600" mb="10px">
              Normal Traffic Statistics
            </Typography>
            <Typography variant="h6" color={colors.grey[100]}>
              Normal Traffic Incidents: {normalData.current || 0} occurrence(s)
            </Typography>
            {normalData.current === 0 && (
              <Typography variant="body1" color={colors.redAccent[500]}>
                Warning: No Normal traffic incidents detected. Verify backend dataset contains attack_cat: Normal.
              </Typography>
            )}
          </Box>
          <Box>
            <Typography variant="h5" color={colors.grey[100]} fontWeight="600" mb="10px">
              Normal Traffic Incidents
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
                No Normal traffic incidents detected. Check backend data for scenario=normal or attack_cat: Normal.
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

export default Normal;
