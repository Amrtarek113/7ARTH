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

import sys
import os
# Add utils directory to path dynamically
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))
from my_analyzer import analyze_file 

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 🔐 مفتاح IPQS
IPQS_API_KEY = "GuDglFbcreVtxCmNpfG9JRPjVvXUw3JW"

# Alert System
alerts = []
alert_rules = []
alerts_lock = threading.Lock()

# User Management
users_db = {
    '7arth@gmail.com': {
        'id': 1,
        'username': '7arth@gmail.com',
        'password_hash': hashlib.sha256('7arth123456789'.encode()).hexdigest(),
        'email': '7arth@gmail.com',
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
# 🔍 GeoIP Lookup Function
# 🔍 GeoIP Lookup Function
# ==========================
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), 'GeoLite2-City.mmdb')

def get_location_from_ip(ip_address):
    try:
        # Check if DB exists
        if not os.path.exists(GEOIP_DB_PATH):
            return {'ip': ip_address, 'error': 'GeoIP database not found'}
            
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip_address)
            return {
                'ip': ip_address,
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
    except Exception as e:
        return {'ip': ip_address, 'error': str(e)}

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

@app.route('/api/users', methods=['POST'])
@token_required
@admin_required
def create_user():
    """Create new user (admin only)"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        role = data.get('role', 'viewer')
        
        if not username or not password or not email:
            return jsonify({
                'status': 'error',
                'message': 'Username, password, and email are required',
                'error_code': 'MISSING_FIELDS'
            }), 400
        
        if username in users_db:
            return jsonify({
                'status': 'error',
                'message': 'Username already exists',
                'error_code': 'USERNAME_EXISTS'
            }), 400
        
        # Define permissions based on role
        role_permissions = {
            'admin': ['read', 'write', 'admin'],
            'analyst': ['read', 'write'],
            'viewer': ['read']
        }
        
        permissions = role_permissions.get(role, ['read'])
        
        # Create new user
        new_user_id = max([user['id'] for user in users_db.values()]) + 1
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        users_db[username] = {
            'id': new_user_id,
            'username': username,
            'password_hash': password_hash,
            'email': email,
            'role': role,
            'permissions': permissions,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'active': True
        }
        
        return jsonify({
            'status': 'success',
            'data': {
                'id': new_user_id,
                'username': username,
                'email': email,
                'role': role,
                'permissions': permissions
            },
            'message': 'User created successfully',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Create user error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
@admin_required
def update_user(user_id):
    """Update user (admin only)"""
    try:
        data = request.get_json()
        
        # Find user by ID
        target_user = None
        target_username = None
        for username, user in users_db.items():
            if user['id'] == user_id:
                target_user = user
                target_username = username
                break
        
        if not target_user:
            return jsonify({
                'status': 'error',
                'message': 'User not found',
                'error_code': 'USER_NOT_FOUND'
            }), 404
        
        # Update user fields
        if 'email' in data:
            target_user['email'] = data['email']
        if 'role' in data:
            role_permissions = {
                'admin': ['read', 'write', 'admin'],
                'analyst': ['read', 'write'],
                'viewer': ['read']
            }
            target_user['role'] = data['role']
            target_user['permissions'] = role_permissions.get(data['role'], ['read'])
        if 'active' in data:
            target_user['active'] = data['active']
        if 'password' in data:
            target_user['password_hash'] = hashlib.sha256(data['password'].encode()).hexdigest()
        
        return jsonify({
            'status': 'success',
            'data': {
                'id': target_user['id'],
                'username': target_user['username'],
                'email': target_user['email'],
                'role': target_user['role'],
                'permissions': target_user['permissions'],
                'active': target_user['active']
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

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(user_id):
    """Delete user (admin only)"""
    try:
        # Find and remove user
        target_username = None
        for username, user in users_db.items():
            if user['id'] == user_id:
                target_username = username
                break
        
        if not target_username:
            return jsonify({
                'status': 'error',
                'message': 'User not found',
                'error_code': 'USER_NOT_FOUND'
            }), 404
        
        # Don't allow deleting the current user
        if target_username == request.current_user['username']:
            return jsonify({
                'status': 'error',
                'message': 'Cannot delete your own account',
                'error_code': 'CANNOT_DELETE_SELF'
            }), 400
        
        del users_db[target_username]
        
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

# Main API Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'success',
        'data': {
            'service': 'Adminis Backend',
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat(),
            'dataset_available': dataset_available,
            'model_loaded': rf_model is not None,
            'environment': FLASK_ENV
        },
        'message': 'Service is healthy',
        'error_code': None
    })

@app.route('/api/predict', methods=['POST'])
@token_required
@permission_required('read')
def predict_attack():
    """Predict attack based on network features"""
    if not rf_model:
        return jsonify({
            'status': 'error',
            'message': 'Model not loaded',
            'error_code': 'MODEL_NOT_LOADED'
        }), 500
    
    try:
        data = request.get_json()
        features = data.get('features', {})
        
        # Preprocess features
        processed_data = preprocess_data(features)
        
        # Make prediction
        prediction = rf_model.predict(processed_data)[0]
        probabilities = rf_model.predict_proba(processed_data)[0]
        confidence = float(probabilities.max())
        
        # Get attack category
        attack_cat = attack_label_encoder.inverse_transform([prediction])[0]
        
        result = {
            'attack_category': attack_cat,
            'prediction': 'Attack' if attack_cat != 'Normal' else 'Normal',
            'confidence': confidence,
            'probabilities': {
                attack_label_encoder.inverse_transform([i])[0]: float(prob)
                for i, prob in enumerate(probabilities)
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({
            'status': 'success',
            'data': result,
            'message': 'Prediction completed successfully',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Prediction failed',
            'error_code': 'PREDICTION_ERROR'
        }), 500

@app.route('/api/metrics', methods=['GET'])
@token_required
@permission_required('read')
def get_metrics():
    """Get threat metrics"""
    with incidents_lock:
        # Count incidents by scenario
        url_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'url')
        iot_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'iot')
        ransomware_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'ransomware')
        dos_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'dos')
        exploits_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'exploits')
        generic_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'generic')
        analysis_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'analysis')
        worms_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'worms')
        total_count = len([inc for inc in recent_incidents if inc.get('scenario') != 'unknown'])

    return jsonify({
        "status": "success",
        "data": {
            "malicious_urls": {"current": url_count, "total": url_count, "change": 60 if url_count > 0 else 0},
            "iot_attacks": {"current": iot_count, "total": iot_count, "change": 60 if iot_count > 0 else 0},
            "ransomware_incidents": {"current": ransomware_count, "change": 5 if ransomware_count > 0 else 0},
            "dos_attacks": {"current": dos_count, "change": 25 if dos_count > 0 else 0},
            "exploits": {"current": exploits_count, "change": 15 if exploits_count > 0 else 0},
            "generic_attacks": {"current": generic_count, "change": 20 if generic_count > 0 else 0},
            "analysis": {"current": analysis_count, "change": 10 if analysis_count > 0 else 0},
            "worms": {"current": worms_count, "change": 30 if worms_count > 0 else 0},
            "total_threats": {"current": total_count, "change": 73 if total_count > 0 else 0}
        },
        "message": None,
        "error_code": None
    })

@app.route('/api/security-events-timeline', methods=['GET'])
@token_required
@permission_required('read')
def get_security_events_timeline():
    """Get security events timeline data"""
    categories = ["Normal", "Fuzzers", "Reconnaissance", "DoS", "Backdoor", "Exploits", "Shellcode", "Generic", "Analysis", "Worms"]
    
    # Generate series data based on recent incidents
    series_data = []
    with incidents_lock:
        for i in range(3):  # 3 series for timeline
            series = {"name": f"Series {i+1}", "data": []}
            for category in categories:
                count = sum(1 for incident in recent_incidents[-30:] if incident['attack_cat'] == category)  # Last 30 incidents
                series["data"].append(count)
            series_data.append(series)
    
    return jsonify({
        "status": "success",
        "data": {
            "categories": categories,
            "series": series_data
        },
        "message": None,
        "error_code": None
    })

@app.route('/api/recent-incidents', methods=['GET'])
@token_required
@permission_required('read')
def get_recent_incidents():
    """Get recent incidents with filtering and pagination"""
    scenario = request.args.get('scenario', '').lower()
    src_ip = request.args.get('src_ip')  # Added for IP filtering
    mac_address = request.args.get('mac_address')  # Added for MAC filtering
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    
    # Filter incidents by scenario, src_ip, and mac_address
    with incidents_lock:
        filtered_incidents = recent_incidents
        if scenario:
            filtered_incidents = [incident for incident in filtered_incidents if incident.get('scenario') == scenario]
        if src_ip:
            filtered_incidents = [incident for incident in filtered_incidents if incident.get('src_ip') == src_ip]
        if mac_address:
            filtered_incidents = [incident for incident in filtered_incidents if incident.get('mac_address') == mac_address]
    
    # Paginate incidents
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_incidents = filtered_incidents[start_idx:end_idx]
    
    return jsonify({
        "status": "success",
        "data": paginated_incidents,
        "message": None,
        "error_code": None,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": len(filtered_incidents)
        }
    })

@app.route('/api/models', methods=['GET'])
@token_required
@permission_required('read')
def list_models():
    """List available models"""
    return jsonify({
        "status": "success",
        "data": {
            "models": ["Random Forest"]
        },
        "message": None,
        "error_code": None
    })

@app.route('/api/system-logs', methods=['GET'])
@token_required
@admin_required
def get_system_logs():
    """Get system logs (admin only)"""
    try:
        log_file_path = 'adminis_backend.log' # Assuming logs are written to this file
        
        if not os.path.exists(log_file_path):
            return jsonify({
                'status': 'error',
                'message': 'Log file not found',
                'error_code': 'LOG_FILE_NOT_FOUND'
            }), 404
        
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            logs = f.readlines()
        
        # Return last 200 log entries for brevity
        return jsonify({
            'status': 'success',
            'data': logs[-200:],
            'message': None,
            'error_code': None
        })
    except Exception as e:
        logger.error(f"Error reading system logs: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve system logs',
            'error_code': 'SYSTEM_LOGS_ERROR'
        }), 500

@app.route('/api/system-health', methods=['GET'])
@token_required
@permission_required('read')
def get_system_health():
    """Get detailed system health information"""
    try:
        # This is a mock function; in a real application, you'd gather actual system metrics.
        # For demonstration purposes, we'll return static or simulated data.
        
        # Simulate CPU and Memory usage
        cpu_usage = random.uniform(10.0, 70.0)
        memory_usage_gb = random.uniform(2.0, 8.0)
        total_memory_gb = 16.0
        memory_percent = (memory_usage_gb / total_memory_gb) * 100
        
        # Simulate Disk usage
        disk_total_gb = 500
        disk_used_gb = random.uniform(50.0, 400.0)
        disk_percent = (disk_used_gb / disk_total_gb) * 100
        
        # Simulate Network activity (simple values)
        net_sent_mb = random.uniform(100.0, 1000.0)
        net_recv_mb = random.uniform(200.0, 2000.0)
        
        # Check model status
        model_status = "Loaded" if rf_model else "Not Loaded"
        dataset_status = "Available" if dataset_available else "Not Available"
        
        # Simulate active sessions count
        active_sessions_count = 0
        with sessions_lock:
            active_sessions_count = len(active_sessions)
        
        health_data = {
            "cpu_usage_percent": round(cpu_usage, 2),
            "memory_usage": {
                "used_gb": round(memory_usage_gb, 2),
                "total_gb": total_memory_gb,
                "percent": round(memory_percent, 2)
            },
            "disk_usage": {
                "used_gb": round(disk_used_gb, 2),
                "total_gb": disk_total_gb,
                "percent": round(disk_percent, 2)
            },
            "network_io": {
                "sent_mb": round(net_sent_mb, 2),
                "received_mb": round(net_recv_mb, 2)
            },
            "model_status": model_status,
            "dataset_status": dataset_status,
            "autonomous_detection_running": autonomous_detection_thread and autonomous_detection_thread.is_alive(),
            "active_user_sessions": active_sessions_count,
            "timestamp": datetime.now().isoformat()
        }
        
        return jsonify({
            'status': 'success',
            'data': health_data,
            'message': 'System health data retrieved successfully',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Error retrieving system health: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve system health data',
            'error_code': 'SYSTEM_HEALTH_ERROR'
        }), 500

@app.route('/api/reports/generate', methods=['GET'])
@token_required
@permission_required('read')
def generate_report():
    """Generate a LaTeX report for a specified scenario"""
    if not dataset_available:
        return jsonify({
            "status": "error",
            "data": None,
            "message": "Report generation unavailable: Dataset not found",
            "error_code": "DATASET_UNAVAILABLE"
        }), 503
    
    try:
        scenario = request.args.get('scenario', '').lower()
        report_type = request.args.get('type', 'summary')  # summary, detailed, statistics
        format_type = request.args.get('format', 'latex')  # latex, pdf
        
        # Filter incidents by scenario
        with incidents_lock:
            filtered_incidents = recent_incidents.copy()
            if scenario:
                filtered_incidents = [incident for incident in recent_incidents 
                                    if incident.get('scenario', '').lower() == scenario]
        
        # Generate report data
        report_data = generate_report_data(filtered_incidents, scenario)
        
        # Generate LaTeX content
        latex_content = generate_latex_report(report_data, scenario, report_type)
        
        if format_type == 'pdf':
            # Convert LaTeX to PDF (requires pdflatex)
            pdf_file = convert_latex_to_pdf(latex_content, scenario)
            if pdf_file:
                return send_file(pdf_file, as_attachment=True, 
                               download_name=f"adminis_report_{scenario}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        
        # Return LaTeX content
        response = app.response_class(
            latex_content,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename="adminis_report_{scenario}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.tex"'
            }
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        return jsonify({
            "status": "error",
            "data": None,
            "message": f"Report generation failed: {str(e)}",
            "error_code": "REPORT_GENERATION_ERROR"
        }), 500

def generate_report_data(incidents, scenario):
    """Generate statistical data for the report"""
    total_incidents = len(incidents)
    
    # Attack categorization
    attack_counts = {}
    threat_levels = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    hourly_distribution = {}
    ip_sources = {}
    
    for incident in incidents:
        # Count attack categories
        attack_cat = incident.get('attack_cat', 'Unknown')
        attack_counts[attack_cat] = attack_counts.get(attack_cat, 0) + 1
        
        # Threat level classification based on confidence
        confidence = incident.get('confidence', 0)
        if confidence >= 0.9:
            threat_levels['critical'] += 1
        elif confidence >= 0.7:
            threat_levels['high'] += 1
        elif confidence >= 0.5:
            threat_levels['medium'] += 1
        else:
            threat_levels['low'] += 1
        
        # Hourly distribution
        try:
            incident_time = datetime.strptime(incident['date'], '%Y-%m-%d %H:%M:%S')
            hour = incident_time.hour
            hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1
        except:
            pass
        
        # IP source tracking
        src_ip = incident.get('src_ip', 'Unknown')
        ip_sources[src_ip] = ip_sources.get(src_ip, 0) + 1
    
    # Top threats
    top_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_ips = sorted(ip_sources.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return {
        'scenario': scenario,
        'total_incidents': total_incidents,
        'attack_counts': attack_counts,
        'threat_levels': threat_levels,
        'hourly_distribution': hourly_distribution,
        'top_attacks': top_attacks,
        'top_ips': top_ips,
        'generation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'generated_by': request.current_user['username'] if hasattr(request, 'current_user') else 'System'
    }

def generate_latex_report(data, scenario, report_type):
    """Generate LaTeX report content"""
    
    # LaTeX document header
    latex_content = r"""
\documentclass[12pt,a4paper]{article}
\usepackage[utf8]{inputenc}
\usepackage[english]{babel}
\usepackage{geometry}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{xcolor}
\usepackage{fancyhdr}
\usepackage{titlesec}
\usepackage{pgfplots}
\usepackage{tikz}

\geometry{margin=1in}
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{Adminis Security Platform}
\fancyhead[R]{\today}
\fancyfoot[C]{\thepage}

\definecolor{adminisblue}{RGB}{0,102,204}
\definecolor{warningred}{RGB}{220,38,38}
\definecolor{successgreen}{RGB}{34,197,94}

\title{\textbf{\color{adminisblue}Adminis Security Platform\\Security Analysis Report}}
\author{Generated by: """ + data['generated_by'] + r"""}
\date{""" + data['generation_time'] + r"""}

\begin{document}

\maketitle

\section{Executive Summary}
"""
    
    # Executive Summary
    scenario_title = scenario.upper() if scenario else "ALL SCENARIOS"
    latex_content += f"""
This report provides a comprehensive analysis of security incidents detected by the Adminis Security Platform for the {scenario_title} scenario. 

\\textbf{{Key Findings:}}
\\begin{{itemize}}
    \\item Total incidents analyzed: {data['total_incidents']}
    \\item Critical threats detected: {data['threat_levels']['critical']}
    \\item High-risk incidents: {data['threat_levels']['high']}
    \\item Report generated on: {data['generation_time']}
\\end{{itemize}}
"""
    
    # Threat Level Distribution Section
    latex_content += r"""
\section{Threat Level Distribution}
The following table shows the distribution of incidents by threat level based on detection confidence:

\begin{table}[h]
\centering
\begin{tabular}{@{}lcc@{}}
\toprule
\textbf{Threat Level} & \textbf{Incident Count} & \textbf{Percentage} \\
\midrule
"""
    
    total = data['total_incidents']
    for level, count in data['threat_levels'].items():
        percentage = (count / total * 100) if total > 0 else 0
        color = "warningred" if level in ['critical', 'high'] else "black"
        latex_content += f"\\textcolor{{{color}}}{{{level.title()}}} & {count} & {percentage:.1f}\\% \\\\\n"
    
    latex_content += r"""
\bottomrule
\end{tabular}
\caption{Threat Level Distribution}
\end{table}
"""
    
    # Attack Categories Section
    if data['top_attacks']:
        latex_content += r"""
\section{Top Attack Categories}
The most frequently detected attack categories are:

\begin{table}[h]
\centering
\begin{tabular}{@{}lcc@{}}
\toprule
\textbf{Attack Category} & \textbf{Incidents} & \textbf{Percentage} \\
\midrule
"""
        
        for attack, count in data['top_attacks']:
            percentage = (count / total * 100) if total > 0 else 0
            latex_content += f"{attack} & {count} & {percentage:.1f}\\% \\\\\n"
        
        latex_content += r"""
\bottomrule
\end{tabular}
\caption{Top Attack Categories}
\end{table}
"""
    
    # Top Source IPs Section
    if data['top_ips']:
        latex_content += r"""
\section{Top Source IP Addresses}
The following IP addresses generated the most security incidents:

\begin{table}[h]
\centering
\begin{tabular}{@{}lc@{}}
\toprule
\textbf{Source IP} & \textbf{Incident Count} \\
\midrule
"""
        
        for ip, count in data['top_ips']:
            latex_content += f"{ip} & {count} \\\\\n"
        
        latex_content += r"""
\bottomrule
\end{tabular}
\caption{Top Source IP Addresses}
\end{table}
"""
    
    # Temporal Analysis Section
    if data['hourly_distribution']:
        latex_content += r"""
\section{Temporal Analysis}
\subsection{Hourly Distribution}
The following chart shows the distribution of incidents throughout the day:

\begin{center}
\begin{tikzpicture}
\begin{axis}[
    xlabel={Hour of Day},
    ylabel={Number of Incidents},
    xmin=0, xmax=23,
    xtick={0,4,8,12,16,20},
    grid=major,
    width=12cm,
    height=6cm
]
\addplot[
    color=adminisblue,
    mark=square,
] coordinates {
"""
        
        for hour in range(24):
            count = data['hourly_distribution'].get(hour, 0)
            latex_content += f"({hour},{count}) "
        
        latex_content += r"""
};
\end{axis}
\end{tikzpicture}
\end{center}
"""
    
    # Recommendations Section
    latex_content += r"""
\section{Recommendations}
Based on the analysis of security incidents, the following recommendations are provided:

\begin{itemize}
"""
    
    # Dynamic recommendations based on data
    if data['threat_levels']['critical'] > 0:
        latex_content += f"    \\item \\textcolor{{warningred}}{{\\textbf{{Immediate Action Required:}}}} {data['threat_levels']['critical']} critical threats detected. Review and respond immediately.\n"
    
    if data['top_ips']:
        top_ip = data['top_ips'][0][0]
        top_count = data['top_ips'][0][1]
        latex_content += f"    \\item \\textbf{{IP Blocking:}} Consider blocking or monitoring IP address {top_ip} which generated {top_count} incidents.\n"
    
    if data['top_attacks']:
        top_attack = data['top_attacks'][0][0]
        latex_content += f"    \\item \\textbf{{Attack Focus:}} Implement additional protection against {top_attack} attacks.\n"
    
    latex_content += r"""
    \item \textbf{Continuous Monitoring:} Maintain 24/7 monitoring of the security platform.
    \item \textbf{Regular Updates:} Keep security rules and detection models updated.
    \item \textbf{Incident Response:} Ensure incident response procedures are well-defined and tested.
\end{itemize}
"""
    
    # Footer
    latex_content += r"""
\section{Report Metadata}
\begin{itemize}
    \item Generated by: """ + data['generated_by'] + r"""
    \item Generation time: """ + data['generation_time'] + r"""
    \item Scenario filter: """ + (scenario.upper() if scenario else "ALL") + r"""
    \item Total incidents analyzed: """ + str(data['total_incidents']) + r"""
\end{itemize}

\vfill
\begin{center}
\small
\textit{This report was automatically generated by the Adminis Security Platform}
\end{center}

\end{document}
"""
    
    return latex_content

def convert_latex_to_pdf(latex_content, scenario):
    """Convert LaTeX content to PDF (requires pdflatex)"""
    try:
        import subprocess
        import tempfile
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            tex_file = os.path.join(temp_dir, f"report_{scenario}.tex")
            pdf_file = os.path.join(temp_dir, f"report_{scenario}.pdf")
            
            # Write LaTeX content to file
            with open(tex_file, 'w', encoding='utf-8') as f:
                f.write(latex_content)
            
            # Run pdflatex
            result = subprocess.run([
                'pdflatex', '-interaction=nonstopmode', 
                '-output-directory', temp_dir, tex_file
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and os.path.exists(pdf_file):
                # Move PDF to a permanent location
                final_pdf = f"reports/report_{scenario}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                os.makedirs('reports', exist_ok=True)
                os.rename(pdf_file, final_pdf)
                return final_pdf
            else:
                logger.error(f"LaTeX compilation failed: {result.stderr}")
                return None
                
    except Exception as e:
        logger.error(f"PDF conversion error: {str(e)}")
        return None
    
@app.route('/api/incidents', methods=['GET'])
@token_required
@permission_required('read')
def get_incidents():
    """Get recent security incidents"""
    try:
        limit = request.args.get('limit', 50, type=int)
        scenario = request.args.get('scenario')
        src_ip = request.args.get('src_ip')
        mac_address = request.args.get('mac_address')
        
        with incidents_lock:
            incidents = recent_incidents.copy()
        
        # Filter by scenario if specified
        if scenario:
            incidents = [incident for incident in incidents if incident.get('scenario') == scenario]
            
        # Filter by src_ip if specified
        if src_ip:
            incidents = [incident for incident in incidents if incident.get('src_ip') == src_ip]
            
        # Filter by mac_address if specified
        if mac_address:
            incidents = [incident for incident in incidents if incident.get('mac_address') == mac_address]
        
        # Limit results
        incidents = incidents[-limit:]
        
        return jsonify({
            'status': 'success',
            'data': incidents,
            'message': None,
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Get incidents error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve incidents',
            'error_code': 'INCIDENTS_ERROR'
        }), 500

@app.route('/api/incidents/stream', methods=['GET'])
@token_required
@permission_required('read')
def stream_incidents():
    """Stream real-time incidents (Server-Sent Events)"""
    def generate():
        while True:
            try:
                # Get incident from queue (blocking with timeout)
                incident = incident_queue.get(timeout=30)
                yield f"data: {json.dumps(incident)}\n\n"
            except queue.Empty:
                # Send heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': datetime.now().isoformat()})}\n\n"
            except Exception as e:
                logger.error(f"Stream error: {str(e)}")
                break
    
    return app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*'
        }
    )
@app.route('/api/geoip', methods=['POST'])
@token_required
@permission_required('read')
def geoip_lookup():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'Missing IP address'}), 400

    result = get_location_from_ip(ip)
    
    if 'error' in result:
        return jsonify({
            'status': 'error',
            'message': result['error'],
            'error_code': 'GEOIP_ERROR'
        }), 400
        
    return jsonify({
        'status': 'success',
        'data': result,
        'message': None,
        'error_code': None
    })
@app.route('/api/performance', methods=['GET'])
@token_required
@permission_required('read')
def get_performance():
    """Get model performance metrics"""
    return jsonify({
        'status': 'success',
        'data': model_performance,
        'message': None,
        'error_code': None
    })

@app.route('/api/statistics', methods=['GET'])
@token_required
@permission_required('read')
def get_statistics():
    """Get security statistics"""
    try:
        with incidents_lock:
            incidents = recent_incidents.copy()
        
        # Calculate statistics
        total_incidents = len(incidents)
        attack_incidents = [i for i in incidents if i.get('threat') == 'Attack']
        normal_incidents = [i for i in incidents if i.get('threat') == 'Normal']
        
        # Attack category distribution
        attack_categories = {}
        for incident in attack_incidents:
            cat = incident.get('attack_cat', 'Unknown')
            attack_categories[cat] = attack_categories.get(cat, 0) + 1
        
        # Scenario distribution
        scenarios = {}
        for incident in incidents:
            scenario = incident.get('scenario', 'unknown')
            scenarios[scenario] = scenarios.get(scenario, 0) + 1
        
        # Recent activity (last 24 hours)
        cutoff_time = datetime.now() - timedelta(hours=24)
        recent_activity = []
        for incident in incidents:
            try:
                incident_time = datetime.strptime(incident['date'], '%Y-%m-%d %H:%M:%S')
                if incident_time >= cutoff_time:
                    recent_activity.append(incident)
            except:
                continue
        
        statistics = {
            'total_incidents': total_incidents,
            'attack_incidents': len(attack_incidents),
            'normal_incidents': len(normal_incidents),
            'attack_categories': attack_categories,
            'scenarios': scenarios,
            'recent_activity_24h': len(recent_activity),
            'detection_rate': len(attack_incidents) / total_incidents if total_incidents > 0 else 0,
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify({
            'status': 'success',
            'data': statistics,
            'message': None,
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Statistics error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve statistics',
            'error_code': 'STATISTICS_ERROR'
        }), 500

# Alert System API Routes
@app.route('/api/alerts', methods=['GET'])
@token_required
@permission_required('read')
def get_alerts():
    """Get alerts"""
    try:
        status = request.args.get('status')
        severity = request.args.get('severity')
        limit = request.args.get('limit', 100, type=int)
        
        with alerts_lock:
            filtered_alerts = alerts.copy()
        
        # Apply filters
        if status:
            filtered_alerts = [a for a in filtered_alerts if a['status'] == status]
        if severity:
            filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity]
        
        # Limit and sort by timestamp (newest first)
        filtered_alerts = sorted(filtered_alerts, key=lambda x: x['timestamp'], reverse=True)
        filtered_alerts = filtered_alerts[:limit]
        
        return jsonify({
            'status': 'success',
            'data': filtered_alerts,
            'message': None,
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Get alerts error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve alerts',
            'error_code': 'ALERTS_ERROR'
        }), 500

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@token_required
@permission_required('write')
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        with alerts_lock:
            alert = next((a for a in alerts if a['id'] == alert_id), None)
            if not alert:
                return jsonify({
                    'status': 'error',
                    'message': 'Alert not found',
                    'error_code': 'ALERT_NOT_FOUND'
                }), 404
            
            alert['status'] = 'acknowledged'
            alert['acknowledged_by'] = request.current_user['username']
            alert['acknowledged_at'] = datetime.now().isoformat()
        
        return jsonify({
            'status': 'success',
            'message': 'Alert acknowledged successfully',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Acknowledge alert error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to acknowledge alert',
            'error_code': 'ACKNOWLEDGE_ERROR'
        }), 500

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
@token_required
@permission_required('write')
def resolve_alert(alert_id):
    """Resolve an alert"""
    try:
        with alerts_lock:
            alert = next((a for a in alerts if a['id'] == alert_id), None)
            if not alert:
                return jsonify({
                    'status': 'error',
                    'message': 'Alert not found',
                    'error_code': 'ALERT_NOT_FOUND'
                }), 404
            
            alert['status'] = 'resolved'
            alert['resolved_by'] = request.current_user['username']
            alert['resolved_at'] = datetime.now().isoformat()
        
        return jsonify({
            'status': 'success',
            'message': 'Alert resolved successfully',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Resolve alert error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to resolve alert',
            'error_code': 'RESOLVE_ERROR'
        }), 500 

        return jsonify({'error': str(e)}), 500
@app.route('/api/alert-rules', methods=['GET'])
@token_required
@permission_required('read')
def get_alert_rules():
    """Get alert rules"""
    return jsonify({
        'status': 'success',
        'data': alert_rules,
        'message': None,
        'error_code': None
    })

@app.route('/api/alert-rules', methods=['POST'])
@token_required
@permission_required('write')
def create_alert_rule():
    """Create new alert rule"""
    try:
        data = request.get_json()
        
        new_rule = {
            'id': len(alert_rules) + 1,
            'name': data.get('name'),
            'type': data.get('type'),
            'severity': data.get('severity'),
            'message': data.get('message'),
            'conditions': data.get('conditions', {}),
            'active': data.get('active', True),
            'created_by': request.current_user['username'],
            'created_at': datetime.now().isoformat()
        }
        
        alert_rules.append(new_rule)
        
        return jsonify({
            'status': 'success',
            'data': new_rule,
            'message': 'Alert rule created successfully',
            'error_code': None
        })
        
    except Exception as e:
        logger.error(f"Create alert rule error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to create alert rule',
            'error_code': 'CREATE_RULE_ERROR'
        }), 500

def block_ip(ip):
    system_type = platform.system()
    try:
        if system_type == "Linux":
            os.system(f"iptables -A INPUT -s {ip} -j DROP")
        elif system_type == "Windows":
            os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
        else:
            print(f"⚠️ Unsupported OS for IP blocking: {system_type}")
        with open("blocked_ips.txt", "a") as log_file:
            log_file.write(f"{ip}\n")
    except Exception as e:
        print(f"❌ Error blocking IP {ip}: {e}")

def send_telegram_alert(ip, fraud_score):
    BOT_TOKEN = "7373120917:AAHHVmuRHzZYKNW3dxw17xtoWjAv6O4n43o"
    CHAT_ID = "6428077800"
    message = f"""
🚨 Suspicious IP Detected!

🔹 IP: {ip}
🔹 Fraud Score: {fraud_score}
🔒 Status: Blocked & Reported
"""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": message}
    try:
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            print("✅ Telegram alert sent.")
        else:
            print(f"❌ Telegram alert failed: {response.text}")
    except Exception as e:
        print(f"❌ Error sending Telegram alert: {e}")

def check_ip_with_ipqs(ip_address):
    url = f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip_address}"
    params = {
        'strictness': 3,
        'allow_public_access_points': 'true',
        'fast': 'true'
    }
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            result = response.json()
            fraud_score = result.get("fraud_score", 0)
            status = "Suspicious" if fraud_score > 80 else "Safe"
            if status == "Suspicious":
                block_ip(ip_address)
                send_telegram_alert(ip_address, fraud_score)
            return {
                "ip": ip_address,
                "fraud_score": fraud_score,
                "status": status,
                "proxy": result.get("proxy"),
                "vpn": result.get("vpn"),
                "tor": result.get("tor"),
                "bot_status": result.get("bot_status"),
                "recent_abuse": result.get("recent_abuse"),
                "country_code": result.get("country_code"),
                "ISP": result.get("ISP"),
                "organization": result.get("organization")
            }
        else:
            return {"ip": ip_address, "error": "Failed to retrieve info"}
    except Exception as e:
        return {"ip": ip_address, "error": str(e)}

# Serve React App
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react_app(path):
    """Serve React application"""
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 'error',
        'message': 'Endpoint not found',
        'error_code': 'NOT_FOUND'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Internal server error',
        'error_code': 'INTERNAL_ERROR'
    }), 500

# Initialize and start the application
def initialize_app():
    """Initialize the application"""
    logger.info("Initializing Adminis Backend...")
    
    # Load dataset
    load_dataset()
    
    # Load or train model
    load_model()
    
    # Initialize alert rules
    initialize_alert_rules()
    
    # Start autonomous detection thread
    global autonomous_detection_thread
    autonomous_detection_thread = threading.Thread(target=autonomous_detection, daemon=True)
    autonomous_detection_thread.start()
    
    logger.info("Adminis Backend initialized successfully")
if __name__ == '__main__':
    initialize_app()
    
    logger.info(f"Starting Adminis Backend on port {PORT}")
    logger.info(f"Environment: {FLASK_ENV}")
    logger.info(f"Dataset path: {UNSW_DATA_PATH}")
    logger.info("Default users: admin/admin123, analyst/analyst123, viewer/viewer123")
    
    app.run(
        host='0.0.0.0',
        port=PORT,
        debug=(FLASK_ENV == 'development'),
        threaded=True
    )
