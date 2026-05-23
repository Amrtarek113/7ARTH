import React, { useState, useEffect, useRef } from 'react';
import { streamIncidents, acknowledgeAlert, resolveAlert, sendToFirewall, getAlerts } from '../services/api';

// Error Boundary
class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null, errorInfo: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ position: 'fixed', top: '20px', left: '50%', transform: 'translateX(-50%)', color: 'red', padding: '8px', background: '#333', marginLeft: '200px' }}>
          <span>Error: {this.state.error?.message || 'Unknown error'}</span>
          <br />
          <span>Stack: {this.state.errorInfo?.componentStack || 'No stack trace'}</span>
        </div>
      );
    }
    return this.props.children;
  }
}

const AlertMessages = ({ token }) => {
  const [alerts, setAlerts] = useState([]);
  const [currentAlert, setCurrentAlert] = useState(null);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);
  const containerRef = useRef(null);

  const testPermissions = localStorage.getItem('permissions') || 'write';

  // Store token in localStorage for api.js
  useEffect(() => {
    if (token && !localStorage.getItem('token')) {
      localStorage.setItem('token', token);
    }
  }, [token]);

  // Patch SVG <rect> elements globally, excluding Nivo charts
  useEffect(() => {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE && !node.closest('.nivo-bar')) {
            const rects = node.querySelectorAll('rect');
            rects.forEach((rect) => {
              const width = parseFloat(rect.getAttribute('width'));
              if (width < 0) {
                console.warn('Found invalid <rect> width:', width, 'Patching to 0', {
                  parent: rect.parentElement?.outerHTML.slice(0, 200),
                  grandparent: rect.parentElement?.parentElement?.outerHTML.slice(0, 200),
                  stack: new Error().stack,
                });
                rect.setAttribute('width', '0');
              }
            });
          }
        });
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, []);

  // Debug DOM
  useEffect(() => {
    if (containerRef.current && open) {
      const rect = containerRef.current.getBoundingClientRect();
      console.log('Container dimensions:', {
        width: rect.width,
        height: rect.height,
        left: rect.left,
        top: rect.top,
      });
      const rectElements = document.querySelectorAll('rect:not(.nivo-bar rect)');
      console.log('DOM <rect> elements (excluding Nivo):', rectElements.length, Array.from(rectElements).map(el => ({
        width: el.getAttribute('width'),
        parent: el.parentElement?.outerHTML.slice(0, 200),
        grandparent: el.parentElement?.parentElement?.outerHTML.slice(0, 200),
      })));
    }
  }, [open]);

  // Log permissions, rendering
  useEffect(() => {
    console.log('Permissions:', testPermissions);
    if (open && currentAlert) {
      console.log('Alert rendered:', currentAlert);
    }
  }, [testPermissions, open, currentAlert]);

  // Fetch alerts
  useEffect(() => {
    const fetchAlerts = async () => {
      const storedToken = localStorage.getItem('token');
      if (!storedToken) {
        setError('No valid token provided.');
        return;
      }

      try {
        const response = await getAlerts({ status: 'active' });
        console.log('getAlerts response:', response);

        const data = Array.isArray(response.data) ? response.data : [];
        if (!data.length) {
          console.warn('No alerts returned from server.');
          setAlerts([]);
          return;
        }

        const mappedAlerts = data
          .map((alert) => {
            if (!alert || !alert.details?.incident) {
              console.warn('Invalid alert structure:', alert);
              return null;
            }
            return {
              id: alert.id,
              message: alert.message,
              severity: alert.severity === 'critical' ? 'error' : alert.severity === 'high' ? 'warning' : 'info',
              timestamp: alert.timestamp,
              incident: alert.details.incident,
              alert_id: alert.id,
            };
          })
          .filter(Boolean);

        console.log('Mapped alerts:', mappedAlerts);
        setAlerts(mappedAlerts);
      } catch (err) {
        console.error('fetchAlerts error:', {
          message: err.message,
          status: err.response?.status,
          data: err.response?.data,
        });
        setError(`Failed to fetch alerts: ${err.message}`);
      }
    };

    fetchAlerts();
  }, []);

  // Stream incidents
  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    if (!storedToken) {
      console.log('No valid token for SSE, skipping stream.');
      setError('No valid token for SSE.');
      return;
    }

    const handleMessage = async (incident) => {
      if (!incident || incident.attack_category === 'Normal' || incident.type === 'heartbeat') {
        console.log('Ignoring incident:', incident);
        return;
      }
      console.log('Received SSE incident:', incident);
      try {
        const response = await getAlerts({ src_ip: incident.src_ip, status: 'active' });
        console.log('getAlerts stream response:', response);
        const matchingAlert = Array.isArray(response.data)
          ? response.data.find(
              (alert) =>
                alert.details?.incident?.src_ip === incident.src_ip &&
                alert.details?.incident?.attack_category === incident.attack_category &&
                alert.details?.incident?.date === incident.date
            )
          : null;

        if (!matchingAlert) {
          console.warn('No matching alert found for incident:', incident);
          return;
        }

        const newAlert = {
          id: matchingAlert.id,
          message: matchingAlert.message,
          severity: matchingAlert.severity === 'critical' ? 'error' : matchingAlert.severity === 'high' ? 'warning' : 'info',
          timestamp: matchingAlert.timestamp,
          incident: matchingAlert.details.incident,
          alert_id: matchingAlert.id,
        };
        console.log('New alert:', newAlert);
        setAlerts((prev) => [...prev, newAlert]);
      } catch (err) {
        console.error('Stream error:', {
          message: err.message,
          status: err.response?.status,
          data: err.response?.data,
        });
        setError(`Stream failed: ${err.message}`);
      }
    };

    const handleError = (error) => {
      console.error('SSE error:', error);
      setError('Incident stream failed. Retrying...');
    };

    const handleOpen = () => {
      console.log('SSE opened');
      setError(null);
    };

    const closeSSE = streamIncidents(storedToken, handleMessage, handleError, handleOpen);

    return () => {
      console.log('Closing SSE');
      closeSSE();
    };
  }, []);

  // Manage alerts display
  useEffect(() => {
    if (alerts.length === 0) {
      setOpen(false);
      setCurrentAlert(null);
      return;
    }

    if (!currentAlert && alerts.length > 0) {
      setCurrentAlert(alerts[0]);
      setOpen(true);
      setAlerts((prev) => prev.slice(1));
    }

    if (currentAlert && open) {
      const timer = setTimeout(() => {
        setOpen(false);
        setTimeout(() => {
          setCurrentAlert(null);
        }, 500);
      }, 10000);
      return () => clearTimeout(timer);
    }
  }, [alerts, currentAlert, open]);

  const handleClose = () => {
    setOpen(false);
    setTimeout(() => setCurrentAlert(null), 500);
  };

  const handleAcknowledge = async () => {
    if (!currentAlert?.alert_id) {
      setError('No alert ID for acknowledgment.');
      return;
    }
    try {
      await acknowledgeAlert(currentAlert.alert_id);
      setActionMessage(`Alert ${currentAlert.alert_id} acknowledged.`);
      setOpen(false);
      setTimeout(() => {
        setCurrentAlert(null);
        setActionMessage(null);
      }, 500);
    } catch (err) {
      console.error('Acknowledge error:', err);
      setError(`Acknowledge failed: ${err.message}`);
    }
  };

  const handleResolve = async () => {
    if (!currentAlert?.alert_id) {
      setError('No alert ID for resolution.');
      return;
    }
    try {
      await resolveAlert(currentAlert.alert_id);
      setActionMessage(`Alert ${currentAlert.alert_id} resolved.`);
      setOpen(false);
      setTimeout(() => {
        setCurrentAlert(null);
        setActionMessage(null);
      }, 500);
    } catch (err) {
      console.error('Resolve error:', err);
      setError(`Resolve failed: ${err.message}`);
    }
  };

  const handleSendToFirewall = async () => {
    if (!currentAlert?.incident?.src_ip) {
      setError('No source IP for firewall.');
      return;
    }
    try {
      const response = await sendToFirewall(currentAlert.incident.src_ip, currentAlert.incident.attack_category);
      setActionMessage(response.message);
      setOpen(false);
      setTimeout(() => {
        setCurrentAlert(null);
        setActionMessage(null);
      }, 500);
    } catch (err) {
      console.error('Firewall error:', err);
      setError(`Firewall failed: ${err.message}`);
    }
  };

  const styles = `
    .alert-container {
      position: fixed;
      top: 20px;
      left: 50%;
      transform: translateX(-50%);
      z-index: 1000;
      font-family: Arial, sans-serif;
      max-width: 600px;
      width: 100%;
      margin-left: 200px;
    }
    .alert-box {
      background-color: #333;
      color: #fff;
      padding: 8px;
      border-radius: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
      border: 1px solid ${currentAlert?.severity === 'error' ? '#f00' : currentAlert?.severity === 'warning' ? '#ff0' : '#00f'};
    }
    .error-box {
      background-color: #f00;
      color: #fff;
      padding: 8px;
      margin-bottom: 8px;
      border-radius: 4px;
    }
    .success-box {
      background-color: #0f0;
      color: #fff;
      padding: 8px;
      margin-bottom: 8px;
      border-radius: 4px;
    }
    .alert-message {
      flex-grow: 1;
      word-break: break-word;
    }
    .alert-timestamp {
      font-size: 0.8rem;
      margin-top: 4px;
      display: block;
    }
    .alert-button {
      background-color: #555;
      color: #fff;
      border: none;
      padding: 4px 8px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.8rem;
    }
    .alert-button:disabled {
      background-color: #888;
      cursor: not-allowed;
    }
    .alert-button:hover:not(:disabled) {
      background-color: #777;
    }
    .alert-container rect {
      width: max(0px, attr(width)) !important;
      min-width: 0 !important;
    }
  `;

  return (
    <ErrorBoundary>
      <div className="alert-container" ref={containerRef}>
        <style>{styles}</style>
        {error && (
          <div className="error-box">
            <span>{error}</span>
          </div>
        )}
        {actionMessage && (
          <div className="success-box">
            <span>{actionMessage}</span>
          </div>
        )}
        {currentAlert && open ? (
          <div className="alert-box">
            <div className="alert-message">
              <span>{currentAlert.message}</span>
              <span className="alert-timestamp">
                {new Date(currentAlert.timestamp).toLocaleString()}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '4px' }}>
              <button
                className="alert-button"
                onClick={handleAcknowledge}
                disabled={!currentAlert.alert_id}
              >
                Ack
              </button>
              <button
                className="alert-button"
                onClick={handleResolve}
                disabled={!currentAlert.alert_id}
              >
                Resolve
              </button>
              <button
                className="alert-button"
                onClick={handleSendToFirewall}
                disabled={!currentAlert.incident?.src_ip}
              >
                Firewall
              </button>
              <button className="alert-button" onClick={handleClose}>
                Close
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </ErrorBoundary>
  );
};
export default AlertMessages;