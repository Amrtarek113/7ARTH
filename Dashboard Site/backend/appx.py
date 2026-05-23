import os
import io
import time
import json
import logging
import random
import threading
import pandas as pd
import numpy as np
from datetime import datetime
from flask import Flask, jsonify, request, send_file, send_from_directory, Blueprint, g
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_swagger_ui import get_swaggerui_blueprint
from marshmallow import Schema, fields, validate, ValidationError
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
from prometheus_flask_exporter import PrometheusMetrics
import joblib

# Import configuration module
from config import get_config

# Custom exceptions
class AdminisError(Exception):
    """Base exception class for Adminis platform"""
    status_code = 500
    error_code = "INTERNAL_ERROR"
    
class DatasetNotFoundError(AdminisError):
    """Exception raised when dataset is not found"""
    status_code = 503
    error_code = "DATASET_UNAVAILABLE"
    
class ModelNotTrainedError(AdminisError):
    """Exception raised when model is not trained"""
    status_code = 503
    error_code = "MODEL_UNAVAILABLE"
    
class ValidationFailedError(AdminisError):
    """Exception raised when validation fails"""
    status_code = 400
    error_code = "VALIDATION_ERROR"

# Request schemas
class PredictionRequestSchema(Schema):
    """Schema for prediction requests"""
    class FeaturesSchema(Schema):
        proto = fields.String(required=True, validate=validate.OneOf(['tcp', 'udp', 'icmp']))
        service = fields.String(required=True)
        state = fields.String(required=True)
        dur = fields.Float(required=True, validate=validate.Range(min=0))
        sbytes = fields.Integer(required=True, validate=validate.Range(min=0))
        dbytes = fields.Integer(required=True, validate=validate.Range(min=0))
        sttl = fields.Integer(required=True, validate=validate.Range(min=0))
        dttl = fields.Integer(required=True, validate=validate.Range(min=0))
        # Add other required fields as needed
        
    features = fields.Nested(FeaturesSchema, required=True)

# Create Flask application
app_config = get_config()
app = Flask(__name__, static_folder='build')
app.config.from_object(app_config)

# JWT configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'devkey-replace-in-production')
jwt = JWTManager(app)

# Setup rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Setup Prometheus metrics
metrics = PrometheusMetrics(app)
metrics.info('app_info', 'Application info', version='1.0.0')

# Setup Swagger UI
SWAGGER_URL = '/api/docs'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Adminis Security Platform API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Setup structured logging
class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging"""
    def format(self, record):
        log_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        if hasattr(record, 'extra'):
            log_record.update(record.extra)
        return json.dumps(log_record)

# Configure logging
handler = logging.StreamHandler()
handler.setFormatter(StructuredFormatter())
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG if app.config['DEBUG'] else logging.INFO)
logger.addHandler(handler)

# Global variables
dataset_available = False
df = None
rf_model = None
attack_label_encoder = LabelEncoder()
cat_encoders = {}
scaler = StandardScaler()
recent_incidents = []
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

# Load dataset and model
def load_dataset():
    """Load the UNSW-NB15 dataset"""
    global df, dataset_available
    
    try:
        logger.info(f"Loading dataset from {app.config['UNSW_DATA_PATH']}")
        df = pd.read_csv(app.config['UNSW_DATA_PATH'])
        dataset_available = True
        logger.info(f"Dataset loaded successfully with {len(df)} records")
        return True
    except Exception as e:
        logger.error(f"Error loading dataset: {str(e)}")
        logger.info("Creating mock dataset...")
        create_mock_dataset()
        return False

def create_mock_dataset():
    """Create a mock dataset for testing"""
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
        'label': [0, 1, 1, 1, 1, 1, 1, 1, 1, 1]
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
    """Load the trained machine learning model"""
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
    """Train the machine learning model"""
    global rf_model, attack_label_encoder, cat_encoders, scaler
    
    if not dataset_available:
        logger.error("Cannot train model: Dataset not available")
        raise DatasetNotFoundError("Cannot train model: Dataset not available")
    
    try:
        start_time = time.time()
        logger.info("Preprocessing data for training")
        # Fit label encoder for attack categories
        attack_label_encoder.fit(df['attack_cat'])
        
        # Encode categorical features
        X = df.drop(['id', 'attack_cat', 'label'], axis=1).copy()
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
        
        train_start_time = time.time()
        rf_model.fit(X_train, y_train)
        train_time = time.time() - train_start_time
        
        # Save model and encoders
        joblib.dump(rf_model, model_file)
        joblib.dump(attack_label_encoder, 'attack_label_encoder.pkl')
        joblib.dump(cat_encoders, 'cat_encoders.pkl')
        joblib.dump(scaler, 'scaler.pkl')
        
        # Evaluate model
        predict_start_time = time.time()
        y_pred = rf_model.predict(X_test)
        predict_time = time.time() - predict_start_time
        
        accuracy = accuracy_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred, average='weighted')
        precision = precision_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')
        
        total_time = time.time() - start_time
        
        logger.info(f"Model trained with accuracy: {accuracy:.4f}")
        model_performance["Random Forest"] = {
            "Accuracy": accuracy,
            "Recall": recall,
            "Precision": precision,
            "F1-Score": f1,
            "time to train": train_time,
            "time to predict": predict_time,
            "total time": total_time
        }
        
        return True
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        raise ModelNotTrainedError(f"Error training model: {str(e)}")

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
    numerical_features = [col for col in df.columns if col not in categorical_features + ['id', 'attack_cat', 'label']]
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
            features = sample.drop(['id', 'attack_cat', 'label']).to_dict()
            
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
                "prediction": "Attack" if attack_cat != "Normal" else "Normal"
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
            
            # Add to recent incidents
            recent_incidents.append(incident)
            
            # Keep only the most recent incidents (up to 100)
            if len(recent_incidents) > 100:
                recent_incidents.pop(0)
            
            # Log detection
            logger.debug(f"Detected {attack_cat} with confidence {prob:.4f}")
            
            # Wait before next detection
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Error in autonomous detection: {str(e)}")
            time.sleep(5)

# Global error handler
@app.errorhandler(AdminisError)
def handle_adminis_error(error):
    """Handle custom exceptions"""
    response = {
        "status": "error",
        "data": None,
        "message": str(error),
        "error_code": error.error_code
    }
    return jsonify(response), error.status_code

# Request logging middleware
@app.before_request
def log_request():
    """Log incoming requests"""
    g.start_time = time.time()
    logger.info(f"Request: {request.method} {request.path}", 
               extra={'remote_addr': request.remote_addr, 'user_agent': request.user_agent.string})

@app.after_request
def log_response(response):
    """Log outgoing responses"""
    if hasattr(g, 'start_time'):
        duration = time.time() - g.start_time
        logger.info(f"Response: {response.status_code} in {duration:.4f}s", 
                   extra={'status': response.status_code, 'duration': duration})
    return response

# Auth Blueprint
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """User login endpoint"""
    try:
        # Ensure request contains JSON
        if not request.is_json:
            return jsonify({
                "status": "error",
                "data": None,
                "message": "Request must be JSON",
                "error_code": "INVALID_REQUEST"
            }), 400
        
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        logger.info(f"Login attempt for username: {username}", extra={'username': username})
        
        # Validate input
        if not username or not password:
            return jsonify({
                "status": "error",
                "data": None,
                "message": "Missing username or password",
                "error_code": "MISSING_CREDENTIALS"
            }), 400
        
        # In a real application, validate against a database
        # This is a simplified example
        if username == 'admin' and password == 'secure_password':
            access_token = create_access_token(identity=username)
            logger.info(f"Login successful for {username}")
            return jsonify({
                "status": "success",
                "data": {
                    "access_token": access_token,
                    "username": username
                },
                "message": "Login successful",
                "error_code": None
            })
        
        logger.warning(f"Invalid login attempt for {username}")
        return jsonify({
            "status": "error",
            "data": None,
            "message": "Invalid credentials",
            "error_code": "INVALID_CREDENTIALS"
        }), 401
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({
            "status": "error",
            "data": None,
            "message": "Login failed due to server error",
            "error_code": "LOGIN_FAILED"
        }), 500

# Health Blueprint
health_bp = Blueprint('health', __name__)

@health_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "success",
        "data": {
            "status": "Backend is running",
            "dataset_available": dataset_available,
            "port": app.config['PORT'],
            "host": "localhost",
            "python_version": ".".join(map(str, os.sys.version_info[:3])),
            "working_directory": os.getcwd()
        },
        "message": None,
        "error_code": None
    })

# Models Blueprint
models_bp = Blueprint('models', __name__)

@models_bp.route('/api/models', methods=['GET'])
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

@models_bp.route('/api/predict', methods=['POST'])
@jwt_required()
@limiter.limit("50 per minute")
@metrics.counter('adminis_predictions_total', 'Number of predictions')
@metrics.histogram('adminis_prediction_latency_seconds', 'Prediction latency')
def predict():
    """Predict attack category using input features"""
    try:
        # Validate input
        schema = PredictionRequestSchema()
        try:
            data = schema.load(request.get_json())
        except ValidationError as err:
            raise ValidationFailedError(f"Validation error: {err.messages}")
        
        features = data.get('features')
        processed_data = preprocess_data(features)
        
        # Make prediction
        prediction = rf_model.predict(processed_data)[0]
        prob = rf_model.predict_proba(processed_data)[0].max()
        attack_cat = attack_label_encoder.inverse_transform([prediction])[0]
        
        # Log prediction
        user_id = get_jwt_identity()
        logger.info(f"Prediction made by user {user_id}: {attack_cat} with confidence {prob:.4f}")
        
        return jsonify({
            "status": "success",
            "data": {
                "prediction": "Attack" if attack_cat != "Normal" else "Normal",
                "confidence": float(prob),
                "attack_cat": attack_cat
            },
            "message": "Prediction completed",
            "error_code": None
        })
    except ValidationFailedError as e:
        raise e
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        return jsonify({
            "status": "error",
            "data": None,
            "message": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@models_bp.route('/api/performance', methods=['GET'])
def get_performance():
    """Get model performance metrics"""
    return jsonify({
        "status": "success",
        "data": model_performance,
        "message": None,
        "error_code": None
    })

# Metrics Blueprint
metrics_bp = Blueprint('metrics', __name__)

@metrics_bp.route('/api/metrics', methods=['GET'])
@jwt_required()
def get_metrics():
    """Get threat metrics"""
    # Count incidents by type
    url_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'url')
    iot_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'iot')
    ransomware_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'ransomware')
    total_count = len(recent_incidents)
    
    return jsonify({
        "status": "success",
        "data": {
            "malicious_urls": {"current": url_count, "total": url_count, "change": 60},
            "iot_attacks": {"current": iot_count, "total": iot_count, "change": 60},
            "ransomware_incidents": {"current": ransomware_count, "change": 5},
            "total_threats": {"current": total_count, "change": 73}
        },
        "message": None,
        "error_code": None
    })

@metrics_bp.route('/api/security-events-timeline', methods=['GET'])
@jwt_required()
def get_security_events_timeline():
    """Get security events timeline data"""
    categories = ["Normal", "Fuzzers", "Reconnaissance", "DoS", "Backdoor", "Exploits", "Shellcode", "Generic", "Analysis", "Worms"]
    
    # Generate series data
    series_data = []
    for i in range(3):
        series_data.append({
            "name": f"Series {i+1}",
            "data": [random.randint(0, 5) for _ in categories]
        })
    
    return jsonify({
        "status": "success",
        "data": {
            "categories": categories,
            "series": series_data
        },
        "message": None,
        "error_code": None
    })

# Incidents Blueprint
incidents_bp = Blueprint('incidents', __name__)

@incidents_bp.route('/api/recent-incidents', methods=['GET'])
@jwt_required()
def get_recent_incidents():
    """Get recent incidents with filtering and pagination"""
    scenario = request.args.get('scenario', '').lower()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    
    # Filter incidents by scenario if provided
    filtered_incidents = recent_incidents
    if scenario:
        filtered_incidents = [incident for incident in recent_incidents if incident.get('scenario') == scenario]
    
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

# Reports Blueprint
reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/api/generate-report', methods=['GET'])
@jwt_required()
def generate_report():
    """Generate a LaTeX report for a specified scenario"""
    if not dataset_available:
        raise DatasetNotFoundError("Report generation unavailable: Dataset not found")
    
    scenario = request.args.get('scenario', '').lower()
    
    # Filter incidents by scenario
    filtered_incidents = recent_incidents
    if scenario:
        filtered_incidents = [incident for incident in recent_incidents if incident.get('scenario') == scenario]
    
    # Generate LaTeX content
    latex_content = r"""
\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{hyperref}
\usepackage{geometry}
\geometry{a4paper, margin=1in}

\title{Adminis Security Report}
\author{Adminis Security Platform}
\date{\today}

\begin{document}

\maketitle

\section{Executive Summary}
This report provides an analysis of security incidents detected by the Adminis security platform.
"""
    
    # Add scenario-specific section
    if scenario:
        latex_content += f"\n\\section{{{scenario.capitalize()} Incidents}}\n"
        latex_content += f"This section focuses on {scenario.capitalize()} incidents detected by the platform.\n"
        
        if scenario == 'ransomware':
            latex_content += "\n\\subsection{Ransomware Cost Analysis}\n"
            latex_content += "The following table shows the estimated cost of ransomware incidents:\n\n"
            latex_content += r"\begin{longtable}{|l|l|l|l|}"
            latex_content += r"\hline"
            latex_content += r"Attack Category & Date & Confidence & Estimated Cost \\ \hline"
            
            for incident in filtered_incidents:
                cost = incident.get('cost', 0)
                latex_content += f"{incident['attack_cat']} & {incident['date']} & {incident['confidence']:.2f} & ${cost} \\\\ \\hline\n"
            
            latex_content += r"\end{longtable}"
        
        elif scenario == 'url':
            latex_content += "\n\\subsection{Malicious URL Analysis}\n"
            latex_content += "The following malicious URLs were detected:\n\n"
            latex_content += r"\begin{longtable}{|l|l|l|}"
            latex_content += r"\hline"
            latex_content += r"Attack Category & Date & URL \\ \hline"
            
            for incident in filtered_incidents:
                url = incident.get('url', 'N/A')
                latex_content += f"{incident['attack_cat']} & {incident['date']} & {url} \\\\ \\hline\n"
            
            latex_content += r"\end{longtable}"
        
        elif scenario == 'iot':
            latex_content += "\n\\subsection{IoT Attack Analysis}\n"
            latex_content += "The following IoT attacks were detected:\n\n"
            latex_content += r"\begin{longtable}{|l|l|l|}"
            latex_content += r"\hline"
            latex_content += r"Attack Category & Date & Confidence \\ \hline"
            
            for incident in filtered_incidents:
                latex_content += f"{incident['attack_cat']} & {incident['date']} & {incident['confidence']:.2f} \\\\ \\hline\n"
            
            latex_content += r"\end{longtable}"
    
    # Add general incidents section
    latex_content += "\n\\section{All Incidents}\n"
    latex_content += "Summary of all incidents detected:\n\n"
    latex_content += r"\begin{longtable}{|l|l|l|l|}"
    latex_content += r"\hline"
    latex_content += r"Attack Category & Date & Scenario & Confidence \\ \hline"
    
    for incident in recent_incidents[:20]:  # Limit to 20 incidents
        incident_scenario = incident.get('scenario', 'unknown')
        latex_content += f"{incident['attack_cat']} & {incident['date']} & {incident_scenario} & {incident['confidence']:.2f} \\\\ \\hline\n"
    
    latex_content += r"\end{longtable}"
    
    # Add conclusion
    latex_content += r"""
\section{Conclusion}
The Adminis security platform has detected and analyzed various security threats. 
For more detailed analysis and mitigation strategies, please contact our security team.
\end{document}
"""
    
    # Create response with LaTeX content
    response = io.BytesIO()
    response.write(latex_content.encode('utf-8'))
    response.seek(0)
    
    return send_file(
        response,
        mimetype='text/plain',
        as_attachment=True,
        download_name=f'adminis_report_{scenario if scenario else "all"}_{datetime.now().strftime("%Y%m%d")}.tex'
    )

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(health_bp)
app.register_blueprint(models_bp)
app.register_blueprint(metrics_bp)
app.register_blueprint(incidents_bp)
app.register_blueprint(reports_bp)

# Setup CORS
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000,http://192.168.56.1:55802').split(',')
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})

# Serve React app
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    """Serve the React frontend"""
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

# Initialize application
def initialize_app():
    """Initialize the application"""
    logger.info("Initializing Adminis Security Platform")
    
    # Load dataset and model
    load_dataset()
    load_model()
    
    # Start autonomous detection thread
    global autonomous_detection_thread
    autonomous_detection_thread = threading.Thread(target=autonomous_detection, daemon=True)
    autonomous_detection_thread.start()
    
    logger.info("Adminis Security Platform initialized")

# Run the application
if __name__ == '__main__':
    initialize_app()
    app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'])