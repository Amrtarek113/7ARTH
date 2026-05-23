import React, { useState, useEffect, Component } from 'react';
import { Box, useTheme, Typography } from '@mui/material';
import { tokens } from '../../theme';
import ThreatSeverityChart from '../../components/threatSeverityChart';
import ProtocolDistributionPie from '../../components/protocolDistributionPie';
import IncidentTimeline from '../../components/incidentTimeline';
import TopSourcesTable from '../../components/topSourcesTable';
import ThreatTrendArea from '../../components/threatTrendArea';
import SummaryCard from '../../components/summaryCard';
import PortActivityChart from '../../components/portActivityChart';
import { getStatistics, getRecentIncidents, getThreatLevel, analyzeFile } from '../../services/api';
import { useNavigate, useLocation } from 'react-router-dom';

// Error Boundary Component
class ErrorBoundary extends Component {
  state = { hasError: false, error: null, errorInfo: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error(`${this.props.componentName || 'ErrorBoundary'} caught:`, error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <Box sx={{ padding: '20px', color: 'red', backgroundColor: '#333', textAlign: 'center' }}>
          <Typography variant="h6">Error in {this.props.componentName || 'Component'}</Typography>
          <Typography>Error: {this.state.error?.message || 'Unknown error'}</Typography>
          <Typography>Stack: {this.state.errorInfo?.componentStack || 'No stack trace'}</Typography>
        </Box>
      );
    }
    return this.props.children;
  }
}

const AnalysisResult = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  const navigate = useNavigate();
  const location = useLocation();
  const [timelineData, setTimelineData] = useState(null);
  const [fileAnalysisData, setFileAnalysisData] = useState(null);
  const [error, setError] = useState(null);

  const attackCategories = [
    'Normal', 'Fuzzers', 'Reconnaissance', 'DoS', 'Backdoor',
    'Exploits', 'Shellcode', 'Generic', 'Analysis', 'Worms',
  ];

  const defaultFileAnalysisData = {
    attack_counts: {},
    total_packets: 0,
    timestamp: new Date().toISOString(),
    threat_level: { low: 0, medium: 0, high: 0, critical: 0 },
    protocol_counts: { TCP: 0, UDP: 0, ICMP: 0 },
    incident_timeline: [],
    source_ips: {},
    port_activity: {},
  };

  useEffect(() => {
    if (location.state?.analysisData) {
      const analysisData = location.state.analysisData.data || location.state.analysisData;
      console.log('File analysis data received:', analysisData);
      const fileAnalysis = {
        ...defaultFileAnalysisData,
        ...analysisData,
        attack_counts: analysisData.attack_counts || analysisData.scenarios || {},
        threat_level: analysisData.threat_level || defaultFileAnalysisData.threat_level,
        protocol_counts: analysisData.protocol_counts || defaultFileAnalysisData.protocol_counts,
        incident_timeline: analysisData.incident_timeline || defaultFileAnalysisData.incident_timeline,
        source_ips: analysisData.source_ips || defaultFileAnalysisData.source_ips,
        port_activity: analysisData.port_activity || defaultFileAnalysisData.port_activity,
      };
      console.log('Processed fileAnalysisData:', fileAnalysis); // Added for debugging
      setFileAnalysisData(fileAnalysis);

      const timeline = {
        categories: attackCategories,
        series: [{
          name: 'Attack Counts',
          data: attackCategories.map(cat => fileAnalysis.attack_counts[cat] || 0),
        }],
      };
      setTimelineData(timeline);
    } else {
      fetchGeneralAnalysisResults();
    }
  }, [location.state, navigate]);

  const fetchGeneralAnalysisResults = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        setError('Please log in to view analysis results');
        navigate('/login');
        return;
      }

      const [statsRes, incidentsRes, threatLevelRes] = await Promise.all([
        getStatistics().catch(err => ({ status: 'success', data: {} })),
        getRecentIncidents('', 1, 30).catch(err => ({ status: 'success', data: [] })),
        getThreatLevel().catch(err => ({ status: 'success', data: { low: 0, medium: 0, high: 0, critical: 0 } })),
      ]);

      if (statsRes.status === 'success') {
        const fileAnalysisData = {
          ...defaultFileAnalysisData,
          attack_counts: statsRes.data.scenarios || {},
          total_packets: statsRes.data.total_packets || 0,
          timestamp: statsRes.data.timestamp || new Date().toISOString(),
          threat_level: threatLevelRes.status === 'success' ? threatLevelRes.data : defaultFileAnalysisData.threat_level,
          protocol_counts: statsRes.data.protocol_counts || defaultFileAnalysisData.protocol_counts,
          incident_timeline: statsRes.data.incident_timeline || defaultFileAnalysisData.incident_timeline,
          source_ips: statsRes.data.source_ips || defaultFileAnalysisData.source_ips,
          port_activity: statsRes.data.port_activity || defaultFileAnalysisData.port_activity,
        };
        setFileAnalysisData(fileAnalysisData);
      } else {
        setError('Invalid statistics response');
        return;
      }

      if (incidentsRes.status === 'success') {
        const timeline = {
          categories: attackCategories,
          series: [{
            name: 'Attack Counts',
            data: attackCategories.map(cat => incidentsRes.data.filter(inc => inc.attack_cat === cat).length),
          }],
        };
        setTimelineData(timeline);
      } else {
        setError('Invalid incidents response');
      }

      setError(null);
    } catch (err) {
      console.error('Fetch error:', err);
      if (err.response?.status === 401) {
        localStorage.removeItem('token');
        setError('Session expired. Please log in again.');
        navigate('/login');
      } else {
        setError(`Error: ${err.response?.data?.message || err.message}. Using fallback data.`);
        setFileAnalysisData(defaultFileAnalysisData);
        setTimelineData({ categories: attackCategories, series: [{ name: 'Attack Counts', data: attackCategories.map(() => 0) }] });
      }
    }
  };

  if (error) {
    return (
      <Box sx={{ paddingLeft: "300px", boxSizing: "border-box", minHeight: "100vh", margin: "20px", textAlign: "center", color: colors.redAccent[500] }}>
        {error}
      </Box>
    );
  }

  if (!timelineData || !fileAnalysisData) {
    return (
      <Box sx={{ paddingLeft: "300px", boxSizing: "border-box", minHeight: "100vh", margin: "20px", textAlign: "center", color: colors.grey[100] }}>
        Loading analysis results...
      </Box>
    );
  }

  const threatSeverityData = fileAnalysisData.threat_level
    ? [
        { severity: 'Low', value: fileAnalysisData.threat_level.low || 0 },
        { severity: 'Medium', value: fileAnalysisData.threat_level.medium || 0 },
        { severity: 'High', value: fileAnalysisData.threat_level.high || 0 },
        { severity: 'Critical', value: fileAnalysisData.threat_level.critical || 0 },
      ]
    : [{ severity: 'No Data', value: 0 }]; // Fallback if threat_level is undefined

  const protocolDistributionData = fileAnalysisData.protocol_counts
    ? [
        { id: 'TCP', value: fileAnalysisData.protocol_counts.TCP || 0 },
        { id: 'UDP', value: fileAnalysisData.protocol_counts.UDP || 0 },
        { id: 'ICMP', value: fileAnalysisData.protocol_counts.ICMP || 0 },
      ]
    : [{ id: 'No Data', value: 0 }];

  const portActivityData = Object.entries(fileAnalysisData.port_activity || {}).map(([port, count]) => ({ port, value: count || 0 }));

  return (
    <ErrorBoundary>
      <Box sx={{ paddingLeft: "300px", boxSizing: "border-box", minHeight: "100vh", margin: "20px" }}>
        <Box
          display="grid"
          gridTemplateColumns="repeat(12, 1fr)"
          gridAutoRows="minmax(300px, auto)"
          gap="20px"
          sx={{ padding: '10px' }}
        >
          <Box gridColumn="span 6" gridRow="span 2" backgroundColor={colors.primary[400]} sx={{ height: '100%', minHeight: '300px', position: 'relative' }}>
            <ErrorBoundary componentName="ThreatSeverityChart">
              <ThreatSeverityChart isDashboard={true} data={threatSeverityData} />
            </ErrorBoundary>
          </Box>
          <Box gridColumn="span 6" gridRow="span 2" backgroundColor={colors.primary[400]} sx={{ height: '100%', minHeight: '300px', position: 'relative' }}>
            <ErrorBoundary componentName="ProtocolDistributionPie">
              <ProtocolDistributionPie data={protocolDistributionData} />
            </ErrorBoundary>
          </Box>
          <Box gridColumn="span 6" gridRow="span 2" backgroundColor={colors.primary[400]} sx={{ height: '100%', minHeight: '300px', position: 'relative' }}>
            <ErrorBoundary componentName="IncidentTimeline">
              <IncidentTimeline isDashboard={true} data={fileAnalysisData.incident_timeline || []} />
            </ErrorBoundary>
          </Box>
          <Box gridColumn="span 6" gridRow="span 2" backgroundColor={colors.primary[400]} sx={{ height: '100%', minHeight: '300px', position: 'relative' }}>
            <ErrorBoundary componentName="ThreatTrendArea">
              <ThreatTrendArea isDashboard={true} data={timelineData} />
            </ErrorBoundary>
          </Box>
          <Box gridColumn="span 12" gridRow="span 2" backgroundColor={colors.primary[400]} sx={{ height: '100%', minHeight: '300px', position: 'relative' }}>
            <ErrorBoundary componentName="TopSourcesTable">
              <TopSourcesTable data={Object.entries(fileAnalysisData.source_ips || {}).map(([ip, { count, attack_types }]) => ({ ip, count: count || 0, attack_types: attack_types || [] }))} />
            </ErrorBoundary>
          </Box>
          <Box gridColumn="span 12" gridRow="span 1" backgroundColor={colors.primary[400]} p={2} sx={{ height: '100%', minHeight: '150px', position: 'relative', mt: 2 }}>
            <ErrorBoundary componentName="SummaryCard">
              <SummaryCard data={fileAnalysisData} />
            </ErrorBoundary>
          </Box>
          <Box gridColumn="span 12" gridRow="span 2" backgroundColor={colors.primary[400]} sx={{ height: '100%', minHeight: '300px', position: 'relative' }}>
            <ErrorBoundary componentName="PortActivityChart">
              <PortActivityChart isDashboard={true} data={portActivityData} />
            </ErrorBoundary>
          </Box>
        </Box>
      </Box>
    </ErrorBoundary>
  );
};

export default AnalysisResult;