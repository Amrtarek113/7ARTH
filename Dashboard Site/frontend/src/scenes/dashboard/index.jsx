import React, { useState, useEffect } from 'react';
import { Box, useTheme } from '@mui/material';
import { tokens } from '../../theme';
import axios from 'axios';
import BarChart from '../../components/BarChart';
import GeographyChart from '../../components/GeographyChart';
import LineChart from '../../components/LineChart';
import PieChart from '../../components/PieChart';
import Header from '../../components/Header';
import StatBox from '../../components/StatBox';
import AlertMessages from '../../components/alertMessages';
import { useNavigate } from 'react-router-dom';

// Error Boundary
class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null, errorInfo: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Dashboard ErrorBoundary caught:', error, errorInfo);
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

axios.defaults.baseURL = 'http://localhost:8080';

const Dashboard = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  const [metrics, setMetrics] = useState(null);
  const [timelineData, setTimelineData] = useState(null);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const [token, setToken] = useState(localStorage.getItem('token'));

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        console.warn('No token found in localStorage');
        setError('Please log in to access the dashboard');
        navigate('/login');
        return;
      }

      const config = { headers: { Authorization: `Bearer ${token}` } };
      console.log('Fetching /api/metrics and /api/security-events-timeline...');
      const [metricsRes, timelineRes] = await Promise.all([
        axios.get('/api/metrics', config),
        axios.get('/api/security-events-timeline', config),
      ]);

      console.log('Raw /api/metrics response:', metricsRes.data);
      console.log('Raw /api/security-events-timeline response:', timelineRes.data);

      if (metricsRes.data.status === 'success' && metricsRes.data.data) {
        const validatedMetrics = {
          malicious_urls: {
            current: Math.max(0, metricsRes.data.data.malicious_urls?.current || 0),
            change: Math.max(0, metricsRes.data.data.malicious_urls?.change || 0),
          },
          iot_attacks: {
            current: Math.max(0, metricsRes.data.data.iot_attacks?.current || 0),
            change: Math.max(0, metricsRes.data.data.iot_attacks?.change || 0),
          },
          ransomware_incidents: {
            current: Math.max(0, metricsRes.data.data.ransomware_incidents?.current || 0),
            change: Math.max(0, metricsRes.data.data.ransomware_incidents?.change || 0),
          },
          total_threats: {
            current: Math.max(0, metricsRes.data.data.total_threats?.current || 0),
            change: Math.max(0, metricsRes.data.data.total_threats?.change || 0),
          },
        };
        console.log('Validated metrics:', validatedMetrics);
        setMetrics(validatedMetrics);
      } else {
        console.warn('Invalid metrics response:', metricsRes.data);
        setError('Invalid metrics response. Using mock data.');
        setMetrics({
          malicious_urls: { current: 10, change: 5 },
          iot_attacks: { current: 20, change: 10 },
          ransomware_incidents: { current: 15, change: 7 },
          total_threats: { current: 45, change: 22 },
        });
      }

      if (timelineRes.data.status === 'success' && timelineRes.data.data) {
        setTimelineData(timelineRes.data.data);
      } else {
        console.warn('Invalid timeline response:', timelineRes.data);
        setError('Invalid timeline response. Check backend logs.');
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
          setMetrics({
            malicious_urls: { current: 10, change: 5 },
            iot_attacks: { current: 20, change: 10 },
            ransomware_incidents: { current: 15, change: 7 },
            total_threats: { current: 45, change: 22 },
          });
        }
      } else if (error.request) {
        setError('No response from backend. Ensure it’s running on http://localhost:8080.');
        setMetrics({
          malicious_urls: { current: 10, change: 5 },
          iot_attacks: { current: 20, change: 10 },
          ransomware_incidents: { current: 15, change: 7 },
          total_threats: { current: 45, change: 22 },
        });
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
        {error}
      </Box>
    );
  }

  if (!metrics || !timelineData) {
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
        Loading dashboard data...
      </Box>
    );
  }

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
        <Header title="DASHBOARD" subtitle="Welcome to your dashboard" />
        <Box
          display="grid"
          gridTemplateColumns="repeat(12, 1fr)"
          gridAutoRows="140px"
          gap="20px"
        >
          <Box gridColumn="span 3" backgroundColor={colors.primary[400]} display="flex" alignItems="center" justifyContent="center">
            <StatBox title={metrics.malicious_urls.current.toString()} subtitle="Malicious URLs" progress="0.5" increase={`+${metrics.malicious_urls.change}%`} />
          </Box>
          <Box gridColumn="span 3" backgroundColor={colors.primary[400]} display="flex" alignItems="center" justifyContent="center">
            <StatBox title={metrics.iot_attacks.current.toString()} subtitle="IoT Attacks" progress="0.75" increase={`+${metrics.iot_attacks.change}%`} />
          </Box>
          <Box gridColumn="span 3" backgroundColor={colors.primary[400]} display="flex" alignItems="center" justifyContent="center">
            <StatBox title={metrics.ransomware_incidents.current.toString()} subtitle="Ransomware" progress="0.3" increase={`+${metrics.ransomware_incidents.change}%`} />
          </Box>
          <Box gridColumn="span 3" backgroundColor={colors.primary[400]} display="flex" alignItems="center" justifyContent="center">
            <StatBox title={metrics.total_threats.current.toString()} subtitle="Total Threats" progress="0.8" increase={`+${metrics.total_threats.change}%`} />
          </Box>
          <Box gridColumn="span 6" gridRow="span 2" backgroundColor={colors.primary[400]} sx={{ height: '400px' }}>
            <ErrorBoundary>
              <BarChart isDashboard={true} metrics={metrics} />
            </ErrorBoundary>
          </Box>
          <Box gridColumn="span 6" gridRow="span 2" backgroundColor={colors.primary[400]}>
            <PieChart timelineData={timelineData} />
          </Box>
          <Box gridColumn="span 6" gridRow="span 2" backgroundColor={colors.primary[400]}>
            <LineChart isDashboard={true} timelineData={timelineData} />
          </Box>
          <Box gridColumn="span 6" gridRow="span 2" backgroundColor={colors.primary[400]}>
            <GeographyChart isDashboard={true} metrics={metrics} />
          </Box>
        </Box>
        <AlertMessages token={token || 'mock-token'} />
      </Box>
    </ErrorBoundary>
  );
};

export default Dashboard;
