import React, { useState, useEffect } from 'react';
import { Box, Typography, useTheme, TextField, Button, Table, TableContainer, TableHead, TableRow, TableCell, TableBody, Paper, CircularProgress } from '@mui/material';
import { tokens } from '../../theme';
import Header from '../../components/Header';
import GeographyChart from '../../components/GeographyChart';
import { useNavigate } from 'react-router-dom';
import { getRecentIncidents, streamIncidents, getGeoIPLocation } from '../../services/api';
import AlertMessages from '../../components/alertMessages';

// Error Boundary
class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null, errorInfo: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('AttackDetection ErrorBoundary caught:', error, errorInfo);
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

const AttackDetection = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  const navigate = useNavigate();

  const [incidents, setIncidents] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [error, setError] = useState(null);
  const [intervalId, setIntervalId] = useState(null);
  const [geolocationData, setGeolocationData] = useState({});
  const [searchLoading, setSearchLoading] = useState(false);

  const checkToken = () => {
    const token = localStorage.getItem('token');
    if (!token) {
      setError('Please log in to access the attack detection data');
      navigate('/login');
      return null;
    }
    return token;
  };

  const fetchIncidents = async (query = '') => {
    const token = checkToken();
    if (!token) return;

    try {
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
      let src_ip = '';
      let mac_address = '';

      if (query) {
        if (ipRegex.test(query)) {
          src_ip = query;
        } else if (macRegex.test(query)) {
          mac_address = query;
        } else {
          setError('Invalid IP or MAC address format');
          setIncidents([]);
          setGeolocationData({});
          return;
        }
      }

      const response = await getRecentIncidents('', 1, 50, src_ip, mac_address);
      if (response.status === 'success' && Array.isArray(response.data)) {
        setIncidents(response.data);
        setError(null);

        // Fetch geolocation for unique IPs
        const ipRegexForGeo = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        const ipSet = new Set(response.data.map(incident => incident.src_ip).filter(ip => ip && typeof ip === 'string' && ipRegexForGeo.test(ip)));
        const geoResults = {};
        for (const ip of ipSet) {
          try {
            const geoResponse = await getGeoIPLocation(ip);
            if (geoResponse.status === 'success' && geoResponse.data) {
              geoResults[ip] = {
                country: geoResponse.data.country || 'Unknown',
                city: geoResponse.data.city || 'Unknown',
                latitude: parseFloat(geoResponse.data.latitude) || 0,
                longitude: parseFloat(geoResponse.data.longitude) || 0,
              };
            } else {
              geoResults[ip] = { country: 'Unknown', city: 'Unknown', latitude: 0, longitude: 0 };
            }
          } catch (error) {
            console.error('GeoIP error for IP:', ip, error.response?.data || error.message);
            geoResults[ip] = { country: 'Failed', city: 'Failed', latitude: 0, longitude: 0 };
          }
          await new Promise(resolve => setTimeout(resolve, 200)); // Rate limiting
        }
        setGeolocationData(geoResults);
      } else {
        setError(response.message || 'Failed to fetch incidents');
        setIncidents([]);
        setGeolocationData({});
      }
    } catch (err) {
      console.error('Fetch incidents error:', err.response?.data || err.message);
      setError(`Error fetching incidents: ${err.message}`);
      setIncidents([]);
      setGeolocationData({});
    }
  };

  useEffect(() => {
    const setupData = async () => {
      const token = checkToken();
      if (!token) return;

      // Initial fetch
      await fetchIncidents();

      // Start streaming if no search query
      let cleanupStream;
      if (!searchQuery.trim()) {
        cleanupStream = streamIncidents(
          token,
          (incident) => {
            setIncidents(prev => {
              const updated = [incident, ...prev].slice(0, 50);
              return updated;
            });
            // Update geolocation for new incident
            const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
            if (incident.src_ip && ipRegex.test(incident.src_ip)) {
              getGeoIPLocation(incident.src_ip).then(geoResponse => {
                if (geoResponse.status === 'success' && geoResponse.data) {
                  setGeolocationData(prev => ({
                    ...prev,
                    [incident.src_ip]: {
                      country: geoResponse.data.country || 'Unknown',
                      city: geoResponse.data.city || 'Unknown',
                      latitude: parseFloat(geoResponse.data.latitude) || 0,
                      longitude: parseFloat(geoResponse.data.longitude) || 0,
                    },
                  }));
                }
              }).catch(error => {
                console.error('GeoIP stream error for IP:', incident.src_ip, error.response?.data || error.message);
                setGeolocationData(prev => ({
                  ...prev,
                  [incident.src_ip]: { country: 'Failed', city: 'Failed', latitude: 0, longitude: 0 },
                }));
              });
            }
          },
          (err) => {
            console.error('Stream incidents error:', err);
            setError('Lost connection to real-time incident stream. Falling back to polling.');
            const id = setInterval(() => fetchIncidents(), 5000);
            setIntervalId(id);
          },
          () => {
            setError(null);
          }
        );
      } else {
        // Use polling when searching
        const id = setInterval(() => fetchIncidents(searchQuery.trim()), 5000);
        setIntervalId(id);
      }

      return () => {
        if (cleanupStream) cleanupStream();
        if (intervalId) clearInterval(intervalId);
      };
    };

    setupData();
  }, [searchQuery]);

  const handleSearch = async () => {
    if (searchQuery.trim()) {
      setSearchLoading(true);
      if (intervalId) clearInterval(intervalId);
      setIncidents([]); // Clear existing incidents
      setGeolocationData({}); // Clear geolocation data
      await fetchIncidents(searchQuery.trim());
      setSearchLoading(false);
    }
  };

  const handleClear = () => {
    setSearchQuery('');
    setError(null);
    setGeolocationData({});
    setIncidents([]);
    fetchIncidents();

    if (intervalId) clearInterval(intervalId);
    const id = setInterval(() => fetchIncidents(), 5000);
    setIntervalId(id);
  };

  const validateInput = (value) => {
    setSearchQuery(value);
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (value && !ipRegex.test(value) && !macRegex.test(value)) {
      setError('Please enter a valid IP (e.g., 192.168.1.1) or MAC address (e.g., 00:14:22:01:23:45)');
    } else {
      setError(null);
    }
  };

  return (
    <ErrorBoundary>
      <Box sx={{ paddingLeft: '300px', boxSizing: 'border-box', minHeight: '100vh', margin: '20px' }}>
        <Header title="ATTACK DETECTION" subtitle="Search and Visualize Attack Locations" />
        <Box mb="20px">
          <Box display="flex" gap="10px" mb="20px">
            <TextField
              label="Search by IP or MAC Address"
              variant="outlined"
              value={searchQuery}
              onChange={(e) => validateInput(e.target.value)}
              fullWidth
              sx={{ backgroundColor: colors.primary[400] }}
              error={!!error}
              helperText={error}
            />
            <Button
              variant="contained"
              color="secondary"
              onClick={handleSearch}
              disabled={!!error || !searchQuery.trim() || searchLoading}
              startIcon={searchLoading ? <CircularProgress size={20} /> : null}
            >
              Search
            </Button>
            <Button
              variant="outlined"
              color="secondary"
              onClick={handleClear}
              disabled={!searchQuery.trim() || searchLoading}
            >
              Clear
            </Button>
          </Box>

          <Box
            height="400px"
            width="100%"
            mb="40px"
            sx={{
              position: 'relative',
              backgroundColor: colors.primary[400],
              overflow: 'hidden',
              borderRadius: '8px',
            }}
          >
            <GeographyChart
              isDashboard={false}
              mode="incidents"
              data={incidents}
              ipAddress={searchQuery.match(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/) ? searchQuery : null}
              macAddress={searchQuery.match(/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/) ? searchQuery : null}
            />
          </Box>

          <Typography variant="h5" color={colors.grey[100]} fontWeight="600" mb="10px">
            Attack Incidents
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
                    <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>Source IP</TableCell>
                    <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>MAC Address</TableCell>
                    <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>Country</TableCell>
                    <TableCell sx={{ color: colors.grey[100], fontWeight: '600' }}>City</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {incidents.map((incident, i) => {
                    const geo = geolocationData[incident.src_ip] || {};
                    return (
                      <TableRow key={`${incident.src_ip || incident.mac_address || 'unknown'}-${i}`}>
                        <TableCell sx={{ color: colors.greenAccent[500] }}>{incident.attack_cat || 'Unknown'}</TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>{incident.date || 'N/A'}</TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>{((incident.confidence || 0) * 100).toFixed(2)}%</TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>{incident.prediction || 'N/A'}</TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>{incident.threat || 'Unknown'}</TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>{incident.scenario || 'Unknown'}</TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>{incident.src_ip || 'Unknown IP'}</TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>{incident.mac_address || 'N/A'}</TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>{geo.country || 'Unknown'}</TableCell>
                        <TableCell sx={{ color: colors.grey[100] }}>{geo.city || 'Unknown'}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Typography color={colors.grey[100]}>
              No incidents found. Try a different IP or MAC address or clear the search.
            </Typography>
          )}
        </Box>
        <Box mt="20px">
          <AlertMessages token={checkToken() || 'mock-token'} />
        </Box>
      </Box>
    </ErrorBoundary>
  );
};
export default AttackDetection;