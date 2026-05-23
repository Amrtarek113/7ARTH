import React, { useState, useEffect, Suspense, lazy, useMemo, useCallback } from 'react';
import { Box, Typography, useTheme } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { tokens } from '../theme';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import { getMetrics, getRecentIncidents, streamIncidents, getGeoIPLocation } from '../services/api';
import { useMap } from 'react-leaflet';
// Dynamic imports for react-leaflet
const MapContainer = lazy(() => import('react-leaflet').then(module => ({ default: module.MapContainer })));
const TileLayer = lazy(() => import('react-leaflet').then(module => ({ default: module.TileLayer })));
const Marker = lazy(() => import('react-leaflet').then(module => ({ default: module.Marker })));
const Popup = lazy(() => import('react-leaflet').then(module => ({ default: module.Popup })));

// Fix Leaflet default marker icons
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.8.0/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.8.0/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.8.0/images/marker-shadow.png',
});

// Geolocation cache management
const GEOLOCATION_CACHE_KEY = 'geolocation_cache';
const CACHE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_CACHE_SIZE = 1000; // Limit cache to 1000 IPs

const getGeolocationCache = () => {
  try {
    const cache = JSON.parse(localStorage.getItem(GEOLOCATION_CACHE_KEY) || '{}');
    const now = Date.now();
    Object.keys(cache).forEach(ip => {
      if (
        now - cache[ip].timestamp > CACHE_EXPIRY_MS ||
        !cache[ip].latitude ||
        !cache[ip].longitude ||
        isNaN(cache[ip].latitude) ||
        isNaN(cache[ip].longitude)
      ) {
        delete cache[ip];
      }
    });
    const keys = Object.keys(cache);
    if (keys.length > MAX_CACHE_SIZE) {
      keys.slice(0, keys.length - MAX_CACHE_SIZE).forEach(ip => delete cache[ip]);
    }
    localStorage.setItem(GEOLOCATION_CACHE_KEY, JSON.stringify(cache));
    return cache;
  } catch (err) {
    console.error('Error accessing geolocation cache:', err);
    return {};
  }
};

const setGeolocationCache = (ip, data) => {
  try {
    const cache = getGeolocationCache();
    cache[ip] = { ...data, timestamp: Date.now() };
    localStorage.setItem(GEOLOCATION_CACHE_KEY, JSON.stringify(cache));
  } catch (err) {
    console.error('Error updating geolocation cache:', err);
  }
};

// Error Boundary Component
class MapErrorBoundary extends React.Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('MapErrorBoundary caught error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <Box m="20px" textAlign="center" color={this.props.colors.redAccent[500]}>
          <Typography variant="h5">
            Error rendering map: {this.state.error?.message || 'Unknown error'}
          </Typography>
          <Typography variant="body2">
            Displaying fallback data. Check console for details or refresh the page.
          </Typography>
          <Box mt="20px">
            {this.props.fallbackData?.map((data, i) => (
              <Typography key={`fallback-${i}`} color={this.props.colors.grey[100]}>
                {data.popup}
              </Typography>
            ))}
          </Box>
        </Box>
      );
    }
    return this.props.children;
  }
}

// MapUpdater Component to handle dynamic map updates
const MapUpdater = ({ markerData, ipAddress, macAddress }) => {
  const map = useMap();

  useEffect(() => {
    if (markerData.length > 0) {
      const validMarkers = markerData.filter(
        marker => !isNaN(marker.latitude) && !isNaN(marker.longitude) && (marker.latitude !== 0 || marker.longitude !== 0)
      );
      if (validMarkers.length > 0) {
        // Prioritize searched IP/MAC address location
        if (ipAddress || macAddress) {
          const searchedMarker = validMarkers.find(
            marker => marker.popup.includes(ipAddress || macAddress)
          );
          if (searchedMarker) {
            try {
              map.setView([searchedMarker.latitude, searchedMarker.longitude], 8);
            } catch (err) {
              console.warn('Failed to set map view for searched location:', err);
            }
            return;
          }
        }
        // Fallback to fitting all markers
        const bounds = validMarkers.map(marker => [marker.latitude, marker.longitude]);
        try {
          map.fitBounds(bounds, { padding: [50, 50], maxZoom: 8 });
        } catch (err) {
          console.warn('Failed to set map bounds:', err);
        }
      } else {
        map.setView([0, 0], 2);
      }
    } else {
      map.setView([0, 0], 2);
    }
  }, [markerData, ipAddress, macAddress, map]);

  return null;
};

// Custom MapWrapper
const MapWrapper = ({ center, zoom, markerData, colors, mapRef, ipAddress, macAddress }) => {
  const debounce = (func, wait) => {
    let timeout;
    return (...args) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => func(...args), wait);
    };
  };

  const invalidateMap = useCallback(() => {
    if (mapRef.current && mapRef.current._loaded && mapRef.current._container) {
      try {
        mapRef.current.invalidateSize();
      } catch (err) {
        console.warn('Failed to invalidate map size:', err);
      }
    }
  }, [mapRef]);

  const debouncedInvalidateMap = useCallback(debounce(invalidateMap, 100), [invalidateMap]);

  useEffect(() => {
    debouncedInvalidateMap();
    window.addEventListener('resize', debouncedInvalidateMap);
    const observer = new ResizeObserver(debouncedInvalidateMap);
    const container = mapRef.current?._container;
    if (container) {
      observer.observe(container);
    }
    return () => {
      window.removeEventListener('resize', debouncedInvalidateMap);
      if (container) {
        observer.unobserve(container);
      }
    };
  }, [debouncedInvalidateMap, mapRef]);

  return (
    <MapContainer
      center={center}
      zoom={zoom}
      style={{ height: '100%', width: '100%', backgroundColor: colors.primary[400] }}
      whenCreated={map => {
        mapRef.current = map;
        setTimeout(() => {
          if (map._loaded) {
            map.invalidateSize();
          }
        }, 100);
      }}
    >
      <TileLayer
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        attribution='© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        minZoom={2}
        maxZoom={18}
      />
      <MapUpdater markerData={markerData} ipAddress={ipAddress} macAddress={macAddress} />
      {markerData.map((marker, i) => (
        <Marker key={`marker-${i}`} position={[marker.latitude, marker.longitude]}>
          <Popup>
            <Typography color={colors.grey[100]}>{marker.popup}</Typography>
          </Popup>
        </Marker>
      ))}
    </MapContainer>
  );
};

const GeographyChart = ({
  isDashboard = false,
  data: externalData = null,
  metrics: externalMetrics = null,
  mode = 'metrics',
  scenario = null,
  ipAddress = null,
  macAddress = null,
}) => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  const navigate = useNavigate();
  const [metrics, setMetrics] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [markerData, setMarkerData] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const mapRef = React.useRef(null);

  const defaultCenter = [0, 0];
  const defaultZoom = 2;

  const checkToken = () => {
    const token = localStorage.getItem('token');
    if (!token) {
      setError('Authentication required. Please log in.');
      navigate('/login');
      return false;
    }
    return token;
  };

  const fetchIncidents = async () => {
    if (!checkToken()) return;
    try {
      const response = await getRecentIncidents(scenario, 1, 50, ipAddress, macAddress);
      if (response.status === 'success' && Array.isArray(response.data)) {
        setIncidents(response.data);
        setError(null);
      } else {
        setError('Invalid incidents response. Check backend logs.');
      }
    } catch (error) {
      console.error('Fetch incidents error:', error.response?.data || error.message);
      setError(`API error: ${error.message}`);
    }
  };

  const fetchMetrics = async () => {
    if (!checkToken()) return;
    try {
      const response = await getMetrics();
      if (response.status === 'success' && response.data) {
        setMetrics(response.data);
        setError(null);
      } else {
        setError('Invalid metrics response. Check backend logs.');
      }
    } catch (error) {
      console.error('Fetch metrics error:', error.response?.data || error.message);
      setError(`API error: ${error.message}`);
    }
  };

  useEffect(() => {
    // If Dashboard, ALWAYS fetch incidents (ignore passed metrics)
    if (isDashboard) {
      fetchIncidents();
      return;
    }

    if (mode === 'metrics' && !externalMetrics) {
      fetchMetrics();
    } else if (mode === 'metrics' && externalMetrics) {
      setMetrics(externalMetrics);
      setError(null);
    } else if (mode === 'incidents' && !externalData) {
      fetchIncidents();
    }
  }, [mode, externalMetrics, scenario, ipAddress, macAddress, isDashboard]);

  useEffect(() => {
    let cleanupStream;
    // Activate stream if:
    // 1. Incidents mode AND no external data (Standard standalone map)
    // OR
    // 2. Dashboard mode (Dashboard map needs live data)
    if (((mode === 'incidents' && !externalData) || isDashboard) && checkToken() && !ipAddress && !macAddress) {
      cleanupStream = streamIncidents(
        checkToken(),
        (data) => {
          setIncidents(prev => {
            const updated = [data, ...prev].slice(0, 50);
            return updated;
          });
        },
        (err) => {
          setError('Lost real-time incident stream. Using polling.');
          const interval = setInterval(fetchIncidents, 5000);
          return () => clearInterval(interval);
        },
        () => {
          setError(null);
        }
      );
    }
    return () => {
      if (cleanupStream) cleanupStream();
    };
  }, [mode, externalData, scenario, ipAddress, macAddress, isDashboard]);

  const geolocateIPs = async (ips) => {
    const results = {};
    const cache = getGeolocationCache();
    // Filter valid IPs
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    const validIPs = ips.filter(ip => ip && typeof ip === 'string' && ipRegex.test(ip.trim()));
    console.log('Valid IPs for geolocation:', validIPs);
    const uncachedIPs = validIPs.filter(ip => !cache[ip]);

    // Use cached data
    validIPs.forEach(ip => {
      if (cache[ip]) {
        results[ip] = {
          country: cache[ip].country,
          city: cache[ip].city,
          latitude: cache[ip].latitude,
          longitude: cache[ip].longitude,
        };
      }
    });

    // Fetch uncached IPs
    if (uncachedIPs.length > 0) {
      setLoading(true);
      for (const ip of uncachedIPs) {
        try {
          const response = await getGeoIPLocation(ip);
          if (response.status === 'success' && response.data) {
            results[ip] = {
              country: response.data.country || 'Unknown',
              city: response.data.city || 'Unknown',
              latitude: parseFloat(response.data.latitude) || 0,
              longitude: parseFloat(response.data.longitude) || 0,
            };
            setGeolocationCache(ip, results[ip]);
          } else {
            results[ip] = { latitude: 0, longitude: 0, country: 'Unknown', city: 'Unknown' };
            setGeolocationCache(ip, results[ip]);
          }
        } catch (error) {
          console.error('GeoIP lookup failed for IP:', ip, error.response?.data || error.message);
          results[ip] = { latitude: 0, longitude: 0, country: 'Failed', city: 'Failed' };
          setGeolocationCache(ip, results[ip]);
        }
        await new Promise(resolve => setTimeout(resolve, 200)); // Rate limiting
      }
      setLoading(false);
    }
    return results;
  };

  const markerDataMemo = useMemo(() => {
    // 1. If external data provided (AttackerDetection), use it
    if (externalData && Array.isArray(externalData)) {
      const ipSet = new Set(externalData.map(incident => incident.src_ip).filter(ip => ip && typeof ip === 'string' && ip !== 'N/A'));
      return { data: externalData, ips: Array.from(ipSet) };
    }

    // 2. If Dashboard OR Standard Incidents Mode, use internal incidents
    if ((mode === 'incidents' || isDashboard) && incidents.length) {
      const ipSet = new Set(incidents.map(incident => incident.src_ip).filter(ip => ip && typeof ip === 'string' && ip !== 'N/A'));
      return { data: incidents, ips: Array.from(ipSet) };
    }

    // 3. Last fallback: Metrics mode (only if NOT dashboard)
    if (mode === 'metrics' && metrics && !isDashboard) {
      return {
        data: [
          { src_ip: '192.168.1.1', attack_cat: 'Malicious URLs', count: metrics.malicious_urls?.current || 0 },
          { src_ip: '10.0.0.1', attack_cat: 'IoT Attacks', count: metrics.iot_attacks?.current || 0 },
          { src_ip: '172.16.0.1', attack_cat: 'Ransomware', count: metrics.ransomware_incidents?.current || 0 },
          { src_ip: '203.0.113.1', attack_cat: 'Total Threats', count: metrics.total_threats?.current || 0 },
        ],
        ips: ['192.168.1.1', '10.0.0.1', '172.16.0.1', '203.0.113.1'],
      };
    }
    return { data: [], ips: [] };
  }, [externalData, incidents, metrics, mode, isDashboard]);

  useEffect(() => {
    const transformData = async () => {
      const { data, ips } = markerDataMemo;
      if (!data.length || !ips.length) {
        setMarkerData([]);
        return;
      }
      try {
        const geoResults = await geolocateIPs(ips);
        const markersMap = new Map();
        data.forEach((incident, index) => {
          const geo = geoResults[incident.src_ip];
          if (
            geo &&
            typeof geo.latitude === 'number' &&
            typeof geo.longitude === 'number' &&
            !isNaN(geo.latitude) &&
            !isNaN(geo.longitude) &&
            (geo.latitude !== 0 || geo.longitude !== 0)
          ) {
            const key = `${geo.latitude}-${geo.longitude}-${incident.src_ip}-${index}`;
            markersMap.set(key, {
              latitude: geo.latitude,
              longitude: geo.longitude,
              popup: `${geo.country}${geo.city ? ', ' + geo.city : ''}: ${incident.attack_cat || 'Unknown'} (${incident.src_ip})`,
            });
          }
        });
        const markers = Array.from(markersMap.values());
        setMarkerData(markers);
      } catch (err) {
        console.error('Transform data error:', err);
        setError('Failed to process map data. Check console for details.');
      }
    };
    transformData();
  }, [markerDataMemo]);

  if (error) {
    return (
      <Box m="20px" textAlign="center" color={colors.redAccent[500]}>
        <Typography variant="h5">{error}</Typography>
      </Box>
    );
  }

  if (loading) {
    return (
      <Box m="20px" textAlign="center" color={colors.grey[100]}>
        <Typography variant="h5">Fetching geolocation data...</Typography>
      </Box>
    );
  }

  if (!markerData.length) {
    return (
      <Box m="20px" textAlign="center" color={colors.grey[100]}>
        <Typography variant="h5">No valid geolocation data available</Typography>
      </Box>
    );
  }

  return (
    <Box
      height={isDashboard ? '300px' : '400px'}
      width="100%"
      sx={{
        position: 'relative',
        '& .leaflet-container': { height: '100%', width: '100%', zIndex: 1 },
        overflow: 'hidden',
      }}
    >
      <MapErrorBoundary colors={colors} fallbackData={markerData}>
        <Suspense
          fallback={
            <Box m="20px" textAlign="center" color={colors.grey[100]}>
              <Typography variant="h5">Initializing map...</Typography>
            </Box>
          }
        >
          <MapWrapper
            center={defaultCenter}
            zoom={defaultZoom}
            markerData={markerData}
            colors={colors}
            mapRef={mapRef}
            ipAddress={ipAddress}
            macAddress={macAddress}
          />
        </Suspense>
      </MapErrorBoundary>
    </Box>
  );
};
export default GeographyChart;