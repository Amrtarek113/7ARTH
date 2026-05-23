import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Mock data for development
const mockData = {
  statistics: {
    status: 'success',
    data: {
      scenarios: {
        normal: 100,
        fuzzers: 10,
        reconnaissance: 5,
        dos: 8,
        backdoor: 3,
        exploits: 2,
        shellcode: 1,
        generic: 4,
        analysis: 0,
        worms: 0,
      },
      attack_incidents: 33,
      total_packets: 1000,
      timestamp: new Date().toISOString(),
      protocol_counts: { TCP: 600, UDP: 300, ICMP: 100 },
      incident_timeline: [
        { timestamp: new Date(Date.now() - 3600000).toISOString(), count: 5 },
        { timestamp: new Date().toISOString(), count: 10 },
      ],
      source_ips: {
        '192.168.1.1': { count: 15, attack_types: ['DoS', 'Reconnaissance'] },
        '10.0.0.1': { count: 10, attack_types: ['Fuzzers'] },
      },
      port_activity: { '80': 200, '443': 150, '22': 50 },
    },
  },
  threatLevel: {
    status: 'success',
    data: { low: 20, medium: 10, high: 3, critical: 0 },
  },
  recentIncidents: {
    status: 'success',
    data: [
      { attack_cat: 'Fuzzers', timestamp: new Date().toISOString() },
      { attack_cat: 'Reconnaissance', timestamp: new Date().toISOString() },
    ],
  },
  analyzeFile: {
    status: 'success',
    data: {
      attack_counts: {
        normal: 50,
        fuzzers: 5,
        reconnaissance: 3,
        dos: 4,
        backdoor: 1,
        exploits: 1,
        shellcode: 0,
        generic: 2,
        analysis: 0,
        worms: 0,
      },
      total_packets: 500,
      timestamp: new Date().toISOString(),
      threat_level: { low: 10, medium: 5, high: 1, critical: 0 },
      protocol_counts: { TCP: 300, UDP: 150, ICMP: 50 },
      incident_timeline: [
        { timestamp: new Date(Date.now() - 1800000).toISOString(), count: 3 },
        { timestamp: new Date().toISOString(), count: 5 },
      ],
      source_ips: {
        '192.168.1.2': { count: 8, attack_types: ['DoS', 'Fuzzers'] },
        '10.0.0.2': { count: 5, attack_types: ['Reconnaissance'] },
      },
      port_activity: { '80': 100, '443': 75, '22': 25 },
    },
  },
};

// Add token to requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token && !config.headers['Content-Type']?.includes('multipart/form-data')) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    console.log('Axios request:', config.url, { headers: config.headers, data: config.data });
    return config;
  },
  (error) => {
    console.error('Axios request error:', error);
    return Promise.reject(error);
  }
);

// Handle 401 and 404 responses
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('Axios response error:', {
      url: error.config?.url,
      status: error.response?.status,
      data: error.response?.data,
      message: error.message,
    });
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    } else if (error.response?.status === 404) {
      // Return mock data for specific endpoints
      const url = error.config.url.split('?')[0];
      if (url.includes('/statistics')) return { data: mockData.statistics };
      if (url.includes('/recent-incidents')) return { data: mockData.recentIncidents };
      if (url.includes('/threat-level')) return { data: mockData.threatLevel };
      if (url.includes('/analyze-file')) return { data: mockData.analyzeFile };
    }
    return Promise.reject(error);
  }
);

// File upload function
export const uploadFile = async (file) => {
  const token = localStorage.getItem('token');
  if (!token) {
    throw new Error('No token found. Please log in.');
  }

  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await axios.post(`${API_URL}/upload`, formData, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  } catch (error) {
    throw error;
  }
};

// File analysis function
export const analyzeFile = async (filename) => {
  try {
    const response = await api.post('/analyze-file', { filename });
    return response.data;
  } catch (error) {
    throw error;
  }
};

export const getMetrics = async () => {
  const response = await api.get('/metrics');
  return response.data;
};

export const getRecentIncidents = async (scenario = '', page = 1, perPage = 10, src_ip = '', mac_address = '') => {
  const params = { page, per_page: perPage };
  if (scenario) params.scenario = scenario;
  if (src_ip) params.src_ip = src_ip;
  if (mac_address) params.mac_address = mac_address;
  const response = await api.get('/recent-incidents', { params });
  return response.data;
};

export const streamIncidents = (token, onMessage, onError, onOpen) => {
  let retryCount = 0;
  const maxRetries = 5;
  const retryDelay = 5000;

  const connectSSE = () => {
    const eventSource = new EventSource(`${API_URL}/incidents/stream?access_token=${token}`);
    
    eventSource.onopen = () => {
      console.log(`SSE connection opened (attempt ${retryCount + 1}/${maxRetries})`);
      retryCount = 0;
      if (onOpen) onOpen();
    };
    
    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'heartbeat') {
          console.log('Heartbeat received:', data);
          return;
        }
        console.log('New incident received:', data);
        if (onMessage) onMessage(data);
      } catch (err) {
        console.error('SSE message parse error:', err);
      }
    };
    
    eventSource.onerror = (err) => {
      console.error('SSE error:', err);
      eventSource.close();
      if (retryCount < maxRetries) {
        retryCount++;
        console.log(`Retrying SSE in ${retryDelay}ms (attempt ${retryCount}/${maxRetries})`);
        setTimeout(connectSSE, retryDelay);
      } else {
        if (onError) onError(new Error('Max SSE retries reached'));
      }
    };

    return eventSource;
  };

  const eventSource = connectSSE();

  return () => {
    console.log('Closing SSE connection');
    eventSource.close();
  };
};

export const getGeoIPLocation = async (ip) => {
  if (!ip || typeof ip !== 'string' || ip.trim() === '') {
    console.error('Invalid IP address provided:', ip);
    throw new Error('IP address is required and must be a non-empty string');
  }
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  if (!ipRegex.test(ip.trim())) {
    console.error('Invalid IP format:', ip);
    throw new Error('Invalid IP address format');
  }
  try {
    const response = await api.post('/geoip', { ip: ip.trim() });
    if (response.data.status !== 'success') {
      console.error('GeoIP response error:', response.data);
      throw new Error(response.data.message || 'GeoIP lookup failed');
    }
    return response.data;
  } catch (error) {
    console.error('GeoIP request failed:', {
      ip,
      status: error.response?.status,
      message: error.response?.data?.message || error.message,
    });
    throw error;
  }
};

export const getThreatLevel = async () => {
  const response = await api.get('/threat-level');
  return response.data;
};

export const getAttackTypes = async () => {
  const response = await api.get('/attack-types');
  return response.data;
};

export const getAttackOrigins = async () => {
  const response = await api.get('/attack-origins');
  return response.data;
};

export const getAttackCategories = async () => {
  const response = await api.get('/attack-categories');
  return response.data;
};

export const getScenarios = async () => {
  const response = await api.get('/scenarios');
  return response.data;
};

export const getAlerts = async (filters = {}) => {
  const response = await api.get('/alerts', { params: filters });
  return response.data;
};

export const acknowledgeAlert = async (alertId) => {
  const response = await api.post(`/alerts/${alertId}/acknowledge`);
  return response.data;
};

export const resolveAlert = async (alertId) => {
  const response = await api.post(`/alerts/${alertId}/resolve`);
  return response.data;
};

export const sendToFirewall = async (ipAddress, attackCategory) => {
  console.log(`Simulating firewall rule creation: Block IP ${ipAddress} for ${attackCategory} attack`);
  return { 
    status: 'success', 
    message: `Firewall rule created to block IP ${ipAddress} for ${attackCategory} attack`,
    rule: {
      action: 'block',
      ip: ipAddress,
      attack_type: attackCategory,
      timestamp: new Date().toISOString(),
    },
  };
};

export const getStatistics = async () => {
  const response = await api.get('/statistics');
  return response.data;
};