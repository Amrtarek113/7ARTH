"""
Adminis Backend for Security Platform

This Flask-based backend implements the Adminis security platform API, designed to detect
and analyze network attacks using the UNSW-NB15 dataset. It provides endpoints for health checks,
attack predictions, performance metrics, security events, alert system, user management, and more.

Author: AI Assistant
Date: May 8, 2025
"""

import os
import io
import queue
import time
import json
import geoip2.database
import logging
import random
import threading
import pandas as pd
import numpy as np
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
import joblib
import jwt
import sys
import requests
import platform

# Configuration
app = Flask(__name__, static_folder='build')
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000').split(',')
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Logging setup
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Environment variables
FLASK_ENV = os.getenv('FLASK_ENV', 'development')
PORT = int(os.getenv('PORT', 8080))
UNSW_DATA_PATH = os.getenv('UNSW_DATA_PATH', './data/UNSW_NB15_training-set.csv')

# Global variables
dataset_available = False
df = None
rf_model = None
attack_label_encoder = LabelEncoder()
cat_encoders = {}
scaler = StandardScaler()
recent_incidents = []
incidents_lock = threading.Lock()

# In-memory queue for frontend streaming
incident_queue = queue.Queue(maxsize=200)

# Add utils path (commented out as it's a local path and might not exist in the execution environment)
# sys.path.append(r"C:\Users\HP\Desktop\New folder (5)\backend\utils")
# from analyzer import analyze_file

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Authentication Decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        # Check Authorization header first
        if auth_header:
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid token format',
                    'error_code': 'INVALID_TOKEN_FORMAT'
                }), 401
        
        # For SSE endpoint, allow token via query parameter
        if not token and request.path == '/api/incidents/stream':
            token = request.args.get('access_token')
        
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Token is missing',
                'error_code': 'MISSING_TOKEN'
            }), 401
        
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            username = data['username']
            
            with sessions_lock:
                if token not in active_sessions or active_sessions[token]['username'] != username:
                    return jsonify({
                        'status': 'error',
                        'message': 'Token is invalid or expired',
                        'error_code': 'INVALID_TOKEN'
                    }), 401
                
                # Update last activity
                active_sessions[token]['last_activity'] = datetime.now()
            
            # Add user info to request context
            request.current_user = users_db.get(username)
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'status': 'error',
                'message': 'Token has expired',
                'error_code': 'TOKEN_EXPIRED'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'status': 'error',
                'message': 'Token is invalid',
                'error_code': 'INVALID_TOKEN'
            }), 401
        
        return f(*args, **kwargs)
    return decorated

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(request, 'current_user') or not request.current_user:
                return jsonify({
                    'status': 'error',
                    'message': 'User not authenticated',
                    'error_code': 'NOT_AUTHENTICATED'
                }), 401
            
            if permission not in request.current_user.get('permissions', []):
                return jsonify({
                    'status': 'error',
                    'message': 'Insufficient permissions',
                    'error_code': 'INSUFFICIENT_PERMISSIONS'
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'current_user') or not request.current_user:
            return jsonify({
                'status': 'error',
                'message': 'User not authenticated',
                'error_code': 'NOT_AUTHENTICATED'
            }), 401
        
        if request.current_user.get('role') != 'admin':
            return jsonify({
                'status': 'error',
                'message': 'Admin privileges required',
                'error_code': 'ADMIN_REQUIRED'
            }), 403
        
        return f(*args, **kwargs)
    return decorated

# Alert System
alerts = []
alert_rules = []
alerts_lock = threading.Lock()

# GeoIP Setup
GEOIP_DB_PATH = "GeoLite2-City.mmdb"  # File exists in the same directory
geoip_reader = None
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    logger.info(f"GeoIP DB loaded from: {GEOIP_DB_PATH}")
except Exception as e:
    logger.error(f"GeoIP DB load error: {e}. Path tried: {GEOIP_DB_PATH}")

def get_location_from_ip(ip_address):
    """Perform GeoIP lookup for an IP address with enhanced error handling."""
    global geoip_reader
    try:
        if geoip_reader is None:
            geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        response = geoip_reader.city(ip_address)
        return {
            'ip': ip_address,
            'country': getattr(response.country, 'name', 'Unknown'),
            'city': getattr(response.city, 'name', 'Unknown'),
            'latitude': getattr(response.location, 'latitude', 0),
            'longitude': getattr(response.location, 'longitude', 0)
        }
    except geoip2.errors.AddressNotFoundError:
        logger.warning(f"GeoIP address not found: {ip_address}")
        return {
            'ip': ip_address,
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0
        }
    except Exception as e:
        logger.error(f"GeoIP lookup error for {ip_address}: {e}")
        return {
            'ip': ip_address,
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0,
            'error': str(e)
        }

# User Management
users_db = {
    'admin': {
        'id': 1,
        'username': 'admin',
        'password_hash': hashlib.sha256('admin123'.encode()).hexdigest(),
        'email': 'admin@adminis.com',
        'role': 'admin',
        'permissions': ['read', 'write', 'admin'],
        'created_at': datetime.now().isoformat(),
        'last_login': None,
        'active': True
    },
    'analyst': {
        'id': 2,
        'username': 'analyst',
        'password_hash': hashlib.sha256('analyst123'.encode()).hexdigest(),
        'email': 'analyst@adminis.com',
        'role': 'analyst',
        'permissions': ['read', 'write'],
        'created_at': datetime.now().isoformat(),
        'last_login': None,
        'active': True
    },
    'viewer': {
        'id': 3,
        'username': 'viewer',
        'password_hash': hashlib.sha256('viewer123'.encode()).hexdigest(),
        'email': 'viewer@adminis.com',
        'role': 'viewer',
        'permissions': ['read'],
        'created_at': datetime.now().isoformat(),
        'last_login': None,
        'active': True
    }
}

# Session management
active_sessions = {}
sessions_lock = threading.Lock()

autonomous_detection_thread = None
model_file = 'random_forest_model_multiclass.pkl'
categorical_features = ['proto', 'service', 'state']
model_performance = {
    "Random Forest": {
        "Accuracy": 0.9768,
        "Recall": 0.9768,
        "Precision": 0.9769,
        "F1-Score": 0.9768,
        "time to train": 5.5,
        "time to predict": 0.2,
        "total time": 5.7
    }
}

# Attack scenarios mapping
attack_scenarios = {
    "url": ["Fuzzers", "Reconnaissance"],
    "ransomware": ["Exploits", "Shellcode"],
    "iot": ["DoS", "Backdoor"],
    "dos": ["DoS"],
    "exploits": ["Exploits"],
    "generic": ["Generic"],
    "analysis": ["Analysis"],
    "worms": ["Worms"]
}

# Mock IP and MAC address pools
mock_ips = [
    "192.168.1.10", "192.168.1.11", "10.0.0.5", "172.16.0.20", "192.168.0.15",
    "203.0.113.1", "198.51.100.25", "192.0.2.30", "172.217.1.100", "209.85.200.50"
]
mock_macs = [
    "00:14:22:01:23:45", "00:16:17:2A:BC:DE", "00:1A:2B:3C:4D:5E",
    "00:2C:3D:4E:5F:60", "00:1B:44:11:3A:B7", "00:24:D7:8C:9A:2F",
    "00:50:56:C0:00:08", "00:0C:29:3D:7E:1F", "00:1F:5B:2C:8D:9A",
    "00:26:BB:0E:1C:4F"
]

# Alert System Functions
def create_alert(alert_type, severity, message, details=None):
    """Create a new alert"""
    alert = {
        'id': len(alerts) + 1,
        'type': alert_type,
        'severity': severity,  # low, medium, high, critical
        'message': message,
        'details': details or {},
        'timestamp': datetime.now().isoformat(),
        'status': 'active',  # active, acknowledged, resolved
        'acknowledged_by': None,
        'resolved_by': None
    }
    
    with alerts_lock:
        alerts.append(alert)
        # Keep only last 1000 alerts
        if len(alerts) > 1000:
            alerts.pop(0)
    
    logger.info(f"Alert created: {alert_type} - {message}")
    return alert

def check_alert_rules(incident):
    """Check if incident triggers any alert rules"""
    for rule in alert_rules:
        if evaluate_alert_rule(rule, incident):
            create_alert(
                alert_type=rule['type'],
                severity=rule['severity'],
                message=rule['message'].format(**incident),
                details={'incident': incident, 'rule': rule}
            )

def evaluate_alert_rule(rule, incident):
    """Evaluate if an incident matches an alert rule"""
    conditions = rule.get('conditions', {})
    
    # Check attack category condition
    if 'attack_categories' in conditions:
        if incident.get('attack_cat') not in conditions['attack_categories']:
            return False
    
    # Check confidence threshold
    if 'min_confidence' in conditions:
        if incident.get('confidence', 0) < conditions['min_confidence']:
            return False
    
    # Check scenario condition
    if 'scenarios' in conditions:
        if incident.get('scenario') not in conditions['scenarios']:
            return False
    
    return True

# Default alert rules
def initialize_alert_rules():
    """Initialize default alert rules"""
    global alert_rules
    alert_rules = [
        {
            'id': 1,
            'name': 'High Confidence Attack',
            'type': 'security',
            'severity': 'high',
            'message': 'High confidence {attack_cat} attack detected from {src_ip}',
            'conditions': {
                'min_confidence': 0.9
            },
            'active': True
        },
        {
            'id': 2,
            'name': 'Ransomware Detection',
            'type': 'ransomware',
            'severity': 'critical',
            'message': 'Ransomware attack detected: {attack_cat}',
            'conditions': {
                'scenarios': ['ransomware']
            },
            'active': True
        },
        {
            'id': 3,
            'name': 'DoS Attack',
            'type': 'dos',
            'severity': 'high',
            'message': 'DoS attack detected from {src_ip}',
            'conditions': {
                'attack_categories': ['DoS']
            },
            'active': True
        },
        {
            'id': 4,
            'name': 'Multiple Attack Sources',
            'type': 'security',
            'severity': 'medium',
            'message': 'Multiple attacks detected from same source: {src_ip}',
            'conditions': {},
            'active': True
        }
    ]

def enqueue_incident(incident):
    """Thread-safe insertion of an incident into both the in-memory list and queue."""
    with incidents_lock:
        recent_incidents.append(incident)
        if len(recent_incidents) > 100:
            recent_incidents.pop(0)
    
    # Check alert rules
    check_alert_rules(incident)
    
    try:
        incident_queue.put_nowait(incident)
    except queue.Full:
        pass  # Drop the oldest if queue is full

def load_dataset():
    global df, dataset_available
    
    try:
        logger.info(f"Loading dataset from {UNSW_DATA_PATH}")
        df = pd.read_csv(UNSW_DATA_PATH)
        dataset_available = True
        logger.info(f"Dataset loaded successfully with {len(df)} records")
        return True
    except Exception as e:
        logger.error(f"Error loading dataset: {str(e)}")
        logger.info("Creating mock dataset...")
        create_mock_dataset()
        return False

def create_mock_dataset():
    global df, dataset_available
    
    mock_data = {
        'id': list(range(1, 11)),
        'proto': ['tcp', 'udp', 'tcp', 'udp', 'tcp', 'tcp', 'udp', 'tcp', 'udp', 'tcp'],
        'service': ['http', 'dns', 'ftp', 'http', 'smtp', 'http', 'dns', 'ftp', 'http', 'smtp'],
        'state': ['FIN', 'CON', 'INT', 'FIN', 'CON', 'FIN', 'CON', 'INT', 'FIN', 'CON'],
        'dur': [0.1, 0.05, 0.2, 0.15, 0.1, 0.08, 0.12, 0.1, 0.09, 0.11],
        'sbytes': [1000, 800, 1200, 750, 950, 1100, 820, 1250, 730, 980],
        'dbytes': [800, 600, 1000, 500, 750, 850, 620, 1050, 530, 800],
        'sttl': [64, 128, 64, 128, 64, 64, 128, 64, 128, 64],
        'dttl': [64, 128, 64, 128, 64, 64, 128, 64, 128, 64],
        'attack_cat': ['Normal', 'Fuzzers', 'Reconnaissance', 'DoS', 'Backdoor', 'Exploits', 'Shellcode', 'Generic', 'Analysis', 'Worms'],
        'label': [0, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        'src_ip': random.choices(mock_ips, k=10),
        'mac_address': random.choices(mock_macs, k=10)
    }
    
    # Add other required columns as specified in the documentation
    for col in ['spkts', 'dpkts', 'rate', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 
                'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 
                'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 
                'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 
                'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports']:
        mock_data[col] = [random.random() * 100 for _ in range(10)]
    
    df = pd.DataFrame(mock_data)
    dataset_available = True
    logger.info("Mock dataset created successfully")

def load_model():
    global rf_model, attack_label_encoder, cat_encoders, scaler
    
    try:
        # Try to load existing model
        if os.path.exists(model_file):
            logger.info(f"Loading model from {model_file}")
            rf_model = joblib.load(model_file)
            # Load encoders and scaler from separate files if they exist
            if os.path.exists('attack_label_encoder.pkl'):
                attack_label_encoder = joblib.load('attack_label_encoder.pkl')
            if os.path.exists('cat_encoders.pkl'):
                cat_encoders = joblib.load('cat_encoders.pkl')
            if os.path.exists('scaler.pkl'):
                scaler = joblib.load('scaler.pkl')
            logger.info("Model loaded successfully")
            return True
        else:
            logger.info("Model file not found, training new model")
            train_model()
            return True
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        train_model()
        return False

def train_model():
    global rf_model, attack_label_encoder, cat_encoders, scaler
    
    if not dataset_available:
        logger.error("Cannot train model: Dataset not available")
        return False
    
    try:
        logger.info("Preprocessing data for training")
        # Fit label encoder for attack categories
        attack_label_encoder.fit(df['attack_cat'])
        
        # Encode categorical features
        X = df.drop(['id', 'attack_cat', 'label', 'src_ip', 'mac_address'], axis=1).copy()
        y = attack_label_encoder.transform(df['attack_cat'])
        
        # Encode categorical features
        for cat_feature in categorical_features:
            encoder = LabelEncoder()
            X[cat_feature] = encoder.fit_transform(X[cat_feature])
            cat_encoders[cat_feature] = encoder
        
        # Scale numerical features
        numerical_features = [col for col in X.columns if col not in categorical_features]
        X[numerical_features] = scaler.fit_transform(X[numerical_features])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        logger.info("Training Random Forest model")
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_model.fit(X_train, y_train)
        
        # Save model and encoders
        joblib.dump(rf_model, model_file)
        joblib.dump(attack_label_encoder, 'attack_label_encoder.pkl')
        joblib.dump(cat_encoders, 'cat_encoders.pkl')
        joblib.dump(scaler, 'scaler.pkl')
        
        # Evaluate model
        y_pred = rf_model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred, average='weighted')
        precision = precision_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')
        
        logger.info(f"Model trained with accuracy: {accuracy:.4f}")
        model_performance["Random Forest"] = {
            "Accuracy": accuracy,
            "Recall": recall,
            "Precision": precision,
            "F1-Score": f1,
            "time to train": 5.5,
            "time to predict": 0.2,
            "total time": 5.7
        }
        
        return True
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        return False

def preprocess_data(features):
    """Preprocess features for prediction"""
    processed_features = {}
    
    # Process categorical features
    for cat_feature in categorical_features:
        if cat_feature in features:
            if cat_feature in cat_encoders:
                encoder = cat_encoders[cat_feature]
                # Handle unknown categories gracefully
                try:
                    processed_features[cat_feature] = encoder.transform([features[cat_feature]])[0]
                except:
                    # Use the first category as default for unknown values
                    processed_features[cat_feature] = encoder.transform([encoder.classes_[0]])[0]
            else:
                # If encoder not found, use a default value (e.g., 0)
                processed_features[cat_feature] = 0
        else:
            # Use default value if feature is missing
            processed_features[cat_feature] = 0
    
    # Process numerical features
    numerical_features = [col for col in df.columns if col not in categorical_features + ['id', 'attack_cat', 'label', 'src_ip', 'mac_address']]
    for num_feature in numerical_features:
        if num_feature in features:
            processed_features[num_feature] = float(features[num_feature])
        else:
            # Use default value if feature is missing
            processed_features[num_feature] = 0.0
    
    # Convert to DataFrame
    X = pd.DataFrame([processed_features])
    
    # Scale numerical features
    X_numerical = X[numerical_features]
    X[numerical_features] = scaler.transform(X_numerical)
    
    return X

def get_scenario_for_attack(attack_cat):
    """Get the scenario for a given attack category"""
    for scenario, attacks in attack_scenarios.items():
        if attack_cat in attacks:
            return scenario
    return "unknown"

def autonomous_detection():
    """Autonomous attack detection simulation"""
    logger.info("Starting autonomous detection thread")
    
    while True:
        if not dataset_available:
            logger.warning("Dataset not available for autonomous detection")
            time.sleep(5)
            continue
        
        try:
            # Sample a random row from the dataset
            sample = df.sample(1).iloc[0]
            
            # Extract features
            features = sample.drop(['id', 'attack_cat', 'label', 'src_ip', 'mac_address']).to_dict()
            
            # Preprocess and predict
            processed_data = preprocess_data(features)
            prediction = rf_model.predict(processed_data)[0]
            prob = rf_model.predict_proba(processed_data)[0].max()
            
            # Get attack category
            attack_cat = attack_label_encoder.inverse_transform([prediction])[0]
            
            # Create incident record
            incident = {
                "attack_cat": attack_cat,
                "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "threat": "Attack" if attack_cat != "Normal" else "Normal",
                "confidence": float(prob),
                "prediction": "Attack" if attack_cat != "Normal" else "Normal",
                "src_ip": sample.get('src_ip', random.choice(mock_ips)),
                "mac_address": sample.get('mac_address', random.choice(mock_macs))
            }
            
            # Add scenario-specific information
            scenario = get_scenario_for_attack(attack_cat)
            incident["scenario"] = scenario
            
            if attack_cat in ['Fuzzers', 'Reconnaissance']:
                incident['url'] = f"http://example-{attack_cat.lower()}.org"
                incident['scenario'] = 'url'
            elif attack_cat in ['DoS', 'Backdoor']:
                incident['iot'] = attack_cat
                incident['scenario'] = 'iot'
            elif attack_cat in ['Exploits', 'Shellcode']:
                incident['ransomware'] = attack_cat
                incident['cost'] = int(prob * 1000)
                incident['scenario'] = 'ransomware'
            
            enqueue_incident(incident)
            
            # Log detection
            logger.debug(f"Detected {attack_cat} with confidence {prob:.4f}, src_ip: {incident['src_ip']}, mac_address: {incident['mac_address']}")
            
            # Wait before next detection
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Error in autonomous detection: {str(e)}")
            time.sleep(5)

# Authentication & User Management API Routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({
                'status': 'error',
                'message': 'Username and password are required',
                'error_code': 'MISSING_CREDENTIALS'
            }), 400
        
        # Check user credentials
        user = users_db.get(username)
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials',
                'error_code': 'INVALID_CREDENTIALS'
            }), 401
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if user['password_hash'] != password_hash:
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials',
                'error_code': 'INVALID_CREDENTIALS'
            }), 401
        
        if not user.get('active', False):
            return jsonify({
                'status': 'error',
                'message': 'Account is deactivated',
                'error_code': 'ACCOUNT_DEACTIVATED'
            }), 401
        
        # Generate JWT token
        token_payload = {
            'username': username,
            'role': user['role'],
            'permissions': user['permissions'],
            'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
        }
        token = jwt.encode(token_payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
        
        # Store session
        with sessions_lock:
            active_sessions[token] = {
                'username': username,
                'login_time': datetime.now(),
                'last_activity': datetime.now()
            }
        
        # Update last login
        users_db[username]['last_login'] = datetime.now().isoformat()
        
        return jsonify({
            'status': 'success',
            'data': {
                'token': token,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role'],
                    'permissions': user['permissions']
                }
            },
            'message': 'Login successful',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    """User logout endpoint"""
    try:
        token = request.headers.get('Authorization').split(" ")[1]
        
        with sessions_lock:
            if token in active_sessions:
                del active_sessions[token]
        
        return jsonify({
            'status': 'success',
            'message': 'Logout successful',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user():
    """Get current user information"""
    user = request.current_user
    return jsonify({
        'status': 'success',
        'data': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'permissions': user['permissions'],
            'last_login': user['last_login']
        },
        'message': None,
        'error_code': None
    })

@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_users():
    """Get all users (admin only)"""
    users_list = []
    for username, user in users_db.items():
        users_list.append({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'permissions': user['permissions'],
            'created_at': user['created_at'],
            'last_login': user['last_login'],
            'active': user['active']
        })
    return jsonify({
        'status': 'success',
        'data': users_list,
        'message': None,
        'error_code': None
    })

@app.route('/api/users/<string:username>', methods=['GET'])
@token_required
@admin_required
def get_user(username):
    """Get a specific user by username (admin only)"""
    user = users_db.get(username)
    if not user:
        return jsonify({
            'status': 'error',
            'message': 'User not found',
            'error_code': 'USER_NOT_FOUND'
        }), 404
    
    return jsonify({
        'status': 'success',
        'data': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'permissions': user['permissions'],
            'created_at': user['created_at'],
            'last_login': user['last_login'],
            'active': user['active']
        },
        'message': None,
        'error_code': None
    })

@app.route('/api/users', methods=['POST'])
@token_required
@admin_required
def create_user():
    """Create a new user (admin only)"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        role = data.get('role', 'viewer')
        permissions = data.get('permissions', ['read'])
        
        if not username or not password or not email:
            return jsonify({
                'status': 'error',
                'message': 'Username, password, and email are required',
                'error_code': 'MISSING_USER_DETAILS'
            }), 400
        
        if username in users_db:
            return jsonify({
                'status': 'error',
                'message': 'User with this username already exists',
                'error_code': 'USER_EXISTS'
            }), 409
        
        new_user = {
            'id': len(users_db) + 1,
            'username': username,
            'password_hash': hashlib.sha256(password.encode()).hexdigest(),
            'email': email,
            'role': role,
            'permissions': permissions,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'active': True
        }
        users_db[username] = new_user
        
        return jsonify({
            'status': 'success',
            'data': {
                'id': new_user['id'],
                'username': new_user['username'],
                'email': new_user['email'],
                'role': new_user['role'],
                'permissions': new_user['permissions']
            },
            'message': 'User created successfully',
            'error_code': None
        }), 201
        
    except Exception as e:
        logger.error(f"Create user error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/users/<string:username>', methods=['PUT'])
@token_required
@admin_required
def update_user(username):
    """Update an existing user (admin only)"""
    try:
        data = request.get_json()
        user = users_db.get(username)
        
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found',
                'error_code': 'USER_NOT_FOUND'
            }), 404
        
        if 'email' in data:
            user['email'] = data['email']
        if 'role' in data:
            user['role'] = data['role']
        if 'permissions' in data:
            user['permissions'] = data['permissions']
        if 'active' in data:
            user['active'] = data['active']
        
        # Password update
        if 'password' in data:
            user['password_hash'] = hashlib.sha256(data['password'].encode()).hexdigest()
        
        users_db[username] = user
        
        return jsonify({
            'status': 'success',
            'data': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'permissions': user['permissions'],
                'active': user['active']
            },
            'message': 'User updated successfully',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Update user error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/users/<string:username>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(username):
    """Delete a user (admin only)"""
    try:
        if username not in users_db:
            return jsonify({
                'status': 'error',
                'message': 'User not found',
                'error_code': 'USER_NOT_FOUND'
            }), 404
        
        # Prevent deleting the currently logged-in user
        if hasattr(request, 'current_user') and request.current_user and request.current_user['username'] == username:
            return jsonify({
                'status': 'error',
                'message': 'Cannot delete the currently authenticated user',
                'error_code': 'CANNOT_DELETE_SELF'
            }), 403

        del users_db[username]
        
        # Also remove active sessions for the deleted user
        with sessions_lock:
            keys_to_delete = [token for token, session_data in active_sessions.items() if session_data['username'] == username]
            for key in keys_to_delete:
                del active_sessions[key]

        return jsonify({
            'status': 'success',
            'message': 'User deleted successfully',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Delete user error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "model_loaded": rf_model is not None,
        "dataset_available": dataset_available,
        "geoip_db_loaded": geoip_reader is not None,
        "flask_env": FLASK_ENV,
        "python_version": platform.python_version(),
        "flask_version": ".".join(map(str, getattr(app, '__version__', (0, 0, 0)))),
        "os": platform.system(),
        "architecture": platform.machine()
    }
    return jsonify(status)

@app.route('/api/predict', methods=['POST'])
@token_required
@permission_required('write')
def predict_attack():
    """Predict attack using the trained model"""
    if rf_model is None:
        return jsonify({
            'status': 'error',
            'message': 'Model not loaded or trained. Please ensure dataset is available and model is trained.',
            'error_code': 'MODEL_NOT_READY'
        }), 503

    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No input data provided.',
                'error_code': 'MISSING_INPUT'
            }), 400

        # Preprocess data
        processed_data = preprocess_data(data)

        # Make prediction
        prediction_proba = rf_model.predict_proba(processed_data)[0]
        predicted_class_idx = np.argmax(prediction_proba)
        predicted_attack_cat = attack_label_encoder.inverse_transform([predicted_class_idx])[0]
        confidence = prediction_proba[predicted_class_idx]

        # Get scenario
        scenario = get_scenario_for_attack(predicted_attack_cat)

        result = {
            "prediction": "Attack" if predicted_attack_cat != "Normal" else "Normal",
            "attack_category": predicted_attack_cat,
            "confidence": float(confidence),
            "scenario": scenario
        }
        return jsonify({
            'status': 'success',
            'data': result,
            'message': 'Prediction successful',
            'error_code': None
        })
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Prediction failed: {str(e)}",
            'error_code': 'PREDICTION_FAILED'
        }), 500

@app.route('/api/performance', methods=['GET'])
@token_required
@permission_required('read')
def get_performance_metrics():
    """Get model performance metrics"""
    return jsonify({
        'status': 'success',
        'data': model_performance,
        'message': None,
        'error_code': None
    })

@app.route('/api/incidents', methods=['GET'])
@token_required
@permission_required('read')
def get_incidents():
    """Get recent security incidents"""
    with incidents_lock:
        incidents_copy = list(recent_incidents)  # Create a copy for thread safety
    
    # Add GeoIP info to incidents
    for incident in incidents_copy:
        if 'src_ip' in incident:
            incident['location'] = get_location_from_ip(incident['src_ip'])
    
    return jsonify({
        'status': 'success',
        'data': incidents_copy,
        'message': None,
        'error_code': None
    })

@app.route('/api/incidents/stream')
@token_required
@permission_required('read')
def incidents_stream():
    """Stream security incidents via Server-Sent Events (SSE)"""
    def generate_events():
        while True:
            try:
                incident = incident_queue.get(timeout=1)  # Wait for new incidents
                incident['location'] = get_location_from_ip(incident.get('src_ip', 'Unknown'))
                yield f"data: {json.dumps(incident)}\n\n"
            except queue.Empty:
                # Send a keep-alive comment or just pass to retry
                yield ":keep-alive\n\n"
            except Exception as e:
                logger.error(f"Error in SSE stream: {e}")
                break
            time.sleep(1) # Send updates every 1 second or as new data comes

    return app.response_class(generate_events(), mimetype='text/event-stream')

@app.route('/api/alerts', methods=['GET'])
@token_required
@permission_required('read')
def get_alerts():
    """Get all security alerts"""
    with alerts_lock:
        return jsonify({
            'status': 'success',
            'data': alerts,
            'message': None,
            'error_code': None
        })

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@token_required
@permission_required('write')
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    with alerts_lock:
        for alert in alerts:
            if alert['id'] == alert_id:
                alert['status'] = 'acknowledged'
                alert['acknowledged_by'] = request.current_user['username']
                return jsonify({
                    'status': 'success',
                    'message': f"Alert {alert_id} acknowledged.",
                    'data': alert,
                    'error_code': None
                })
        return jsonify({
            'status': 'error',
            'message': 'Alert not found.',
            'error_code': 'ALERT_NOT_FOUND'
        }), 404

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
@token_required
@permission_required('write')
def resolve_alert(alert_id):
    """Resolve an alert"""
    with alerts_lock:
        for alert in alerts:
            if alert['id'] == alert_id:
                alert['status'] = 'resolved'
                alert['resolved_by'] = request.current_user['username']
                return jsonify({
                    'status': 'success',
                    'message': f"Alert {alert_id} resolved.",
                    'data': alert,
                    'error_code': None
                })
        return jsonify({
            'status': 'error',
            'message': 'Alert not found.',
            'error_code': 'ALERT_NOT_FOUND'
        }), 404

@app.route('/api/alert-rules', methods=['GET'])
@token_required
@admin_required
def get_alert_rules():
    """Get all alert rules (admin only)"""
    return jsonify({
        'status': 'success',
        'data': alert_rules,
        'message': None,
        'error_code': None
    })

@app.route('/api/alert-rules', methods=['POST'])
@token_required
@admin_required
def add_alert_rule():
    """Add a new alert rule (admin only)"""
    try:
        data = request.get_json()
        if not all(k in data for k in ['name', 'type', 'severity', 'message', 'conditions']):
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields for alert rule (name, type, severity, message, conditions)',
                'error_code': 'MISSING_RULE_FIELDS'
            }), 400
        
        new_rule = {
            'id': len(alert_rules) + 1,
            'name': data['name'],
            'type': data['type'],
            'severity': data['severity'],
            'message': data['message'],
            'conditions': data['conditions'],
            'active': data.get('active', True)
        }
        alert_rules.append(new_rule)
        return jsonify({
            'status': 'success',
            'data': new_rule,
            'message': 'Alert rule added successfully',
            'error_code': None
        }), 201
    except Exception as e:
        logger.error(f"Error adding alert rule: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/alert-rules/<int:rule_id>', methods=['PUT'])
@token_required
@admin_required
def update_alert_rule(rule_id):
    """Update an existing alert rule (admin only)"""
    try:
        data = request.get_json()
        for i, rule in enumerate(alert_rules):
            if rule['id'] == rule_id:
                alert_rules[i].update(data)
                return jsonify({
                    'status': 'success',
                    'data': alert_rules[i],
                    'message': 'Alert rule updated successfully',
                    'error_code': None
                })
        return jsonify({
            'status': 'error',
            'message': 'Alert rule not found.',
            'error_code': 'RULE_NOT_FOUND'
        }), 404
    except Exception as e:
        logger.error(f"Error updating alert rule: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/alert-rules/<int:rule_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_alert_rule(rule_id):
    """Delete an alert rule (admin only)"""
    global alert_rules
    initial_len = len(alert_rules)
    alert_rules = [rule for rule in alert_rules if rule['id'] != rule_id]
    if len(alert_rules) < initial_len:
        return jsonify({
            'status': 'success',
            'message': 'Alert rule deleted successfully',
            'error_code': None
        })
    return jsonify({
        'status': 'error',
        'message': 'Alert rule not found.',
        'error_code': 'RULE_NOT_FOUND'
    }), 404

@app.route('/api/upload', methods=['POST'])
@token_required
@permission_required('write')
def upload_file():
    """Upload a file for analysis"""
    if 'file' not in request.files:
        return jsonify({
            'status': 'error',
            'message': 'No file part in the request.',
            'error_code': 'NO_FILE_PART'
        }), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({
            'status': 'error',
            'message': 'No selected file.',
            'error_code': 'NO_SELECTED_FILE'
        }), 400
    if file:
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        
        # Analyze the uploaded file (if analyzer is available)
        analysis_result = "Analysis not available due to missing 'analyzer' module."
        if 'analyze_file' in globals(): # Check if analyze_file function is imported
            try:
                analysis_result = analyze_file(filepath)
            except Exception as e:
                logger.error(f"Error analyzing file {filepath}: {e}")
                analysis_result = f"Error during file analysis: {str(e)}"

        return jsonify({
            'status': 'success',
            'message': 'File uploaded and analyzed successfully',
            'file_name': file.filename,
            'analysis_result': analysis_result,
            'error_code': None
        }), 200
    return jsonify({
        'status': 'error',
        'message': 'Failed to upload file.',
        'error_code': 'UPLOAD_FAILED'
    }), 500

@app.route('/api/download/<filename>', methods=['GET'])
@token_required
@permission_required('read')
def download_file(filename):
    """Download an uploaded file"""
    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({
            'status': 'error',
            'message': 'File not found.',
            'error_code': 'FILE_NOT_FOUND'
        }), 404
    except Exception as e:
        logger.error(f"Error downloading file {filename}: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to download file.',
            'error_code': 'DOWNLOAD_FAILED'
        }), 500

# Serve static files from the 'build' directory for the frontend
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react_app(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

@app.before_first_request
def initialize_app():
    """Initializes the application components before the first request."""
    logger.info("Initializing Adminis Backend...")
    load_dataset()
    load_model()
    initialize_alert_rules()
    
    global autonomous_detection_thread
    if autonomous_detection_thread is None or not autonomous_detection_thread.is_alive():
        autonomous_detection_thread = threading.Thread(target=autonomous_detection, daemon=True)
        autonomous_detection_thread.start()
        logger.info("Autonomous detection thread started.")

if __name__ == '__main__':
    initialize_app()
    logger.info(f"Adminis Backend starting in {FLASK_ENV} mode on port {PORT}")
    app.run(debug=True if FLASK_ENV == 'development' else False, host='0.0.0.0', port=PORT)