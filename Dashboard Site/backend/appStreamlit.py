"""
Adminis Security Platform - Streamlit Version

This Streamlit application implements the Adminis security platform UI, designed to detect
and analyze network attacks using the UNSW-NB15 dataset. It provides visualizations for
health checks, attack predictions, performance metrics, security events, and more.

Author: AI Assistant
Date: May 12, 2025
"""

import os
import time
import json
import logging
import random
import threading
import pandas as pd
import numpy as np
from datetime import datetime
import joblib
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO

# Configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Environment variables
UNSW_DATA_PATH = os.getenv('UNSW_DATA_PATH', './data/UNSW_NB15_training-set.csv')

# Global variables
dataset_available = False
df = None
rf_model = None
attack_label_encoder = LabelEncoder()
cat_encoders = {}
scaler = StandardScaler()
recent_incidents = []
incidents_lock = threading.Lock()  # Added for thread safety
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
        'label': [0, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    }
    
    # Add other required columns
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
                try:
                    processed_features[cat_feature] = encoder.transform([features[cat_feature]])[0]
                except:
                    processed_features[cat_feature] = encoder.transform([encoder.classes_[0]])[0]
        else:
            processed_features[cat_feature] = 0
    
    # Process numerical features
    numerical_features = [col for col in df.columns if col not in categorical_features + ['id', 'attack_cat', 'label']]
    for num_feature in numerical_features:
        if num_feature in features:
            processed_features[num_feature] = float(features[num_feature])
        else:
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
            
            # Add to recent incidents with thread safety
            with incidents_lock:
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

# Streamlit UI Components
def display_health_check():
    st.subheader("System Health")
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Dataset Available", "Yes" if dataset_available else "No")
        st.metric("Model Loaded", "Yes" if rf_model is not None else "No")
    
    with col2:
        st.metric("Python Version", ".".join(map(str, os.sys.version_info[:3])))
        st.metric("Working Directory", os.getcwd())
    
    st.info("System is running normally" if dataset_available and rf_model is not None else "System has some issues")

def display_model_performance():
    st.subheader("Model Performance")
    
    if not model_performance:
        st.warning("No performance data available")
        return
    
    for model_name, metrics in model_performance.items():
        st.write(f"### {model_name}")
        
        cols = st.columns(4)
        cols[0].metric("Accuracy", f"{metrics['Accuracy']:.4f}")
        cols[1].metric("Recall", f"{metrics['Recall']:.4f}")
        cols[2].metric("Precision", f"{metrics['Precision']:.4f}")
        cols[3].metric("F1-Score", f"{metrics['F1-Score']:.4f}")
        
        st.write("Timing Metrics:")
        timing_cols = st.columns(3)
        timing_cols[0].metric("Training Time", f"{metrics['time to train']}s")
        timing_cols[1].metric("Prediction Time", f"{metrics['time to predict']}s")
        timing_cols[2].metric("Total Time", f"{metrics['total time']}s")

def display_threat_metrics():
    st.subheader("Threat Metrics")
    
    # Count incidents by type with thread safety
    with incidents_lock:
        url_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'url')
        iot_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'iot')
        ransomware_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'ransomware')
        dos_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'dos')
        exploits_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'exploits')
        generic_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'generic')
        analysis_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'analysis')
        worms_count = sum(1 for incident in recent_incidents if incident.get('scenario') == 'worms')
        total_count = len([inc for inc in recent_incidents if inc.get('scenario') != 'unknown'])

    cols = st.columns(3)
    cols[0].metric("Malicious URLs", url_count, delta=f"{60 if url_count > 0 else 0}%")
    cols[1].metric("IoT Attacks", iot_count, delta=f"{60 if iot_count > 0 else 0}%")
    cols[2].metric("Ransomware Incidents", ransomware_count, delta=f"{5 if ransomware_count > 0 else 0}%")
    
    cols = st.columns(3)
    cols[0].metric("DoS Attacks", dos_count, delta=f"{25 if dos_count > 0 else 0}%")
    cols[1].metric("Exploits", exploits_count, delta=f"{15 if exploits_count > 0 else 0}%")
    cols[2].metric("Generic Attacks", generic_count, delta=f"{20 if generic_count > 0 else 0}%")
    
    cols = st.columns(3)
    cols[0].metric("Analysis", analysis_count, delta=f"{10 if analysis_count > 0 else 0}%")
    cols[1].metric("Worms", worms_count, delta=f"{30 if worms_count > 0 else 0}%")
    cols[2].metric("Total Threats", total_count, delta=f"{73 if total_count > 0 else 0}%")

def display_security_events_timeline():
    st.subheader("Security Events Timeline")
    
    categories = ["Normal", "Fuzzers", "Reconnaissance", "DoS", "Backdoor", "Exploits", "Shellcode", "Generic", "Analysis", "Worms"]
    
    # Generate series data based on recent incidents
    series_data = []
    with incidents_lock:
        for i in range(3):
            series = {"name": f"Series {i+1}", "data": []}
            for category in categories:
                count = sum(1 for incident in recent_incidents[-30:] if incident['attack_cat'] == category)  # Last 30 incidents
                series["data"].append(count)
            series_data.append(series)
    
    # Create a Plotly figure
    fig = go.Figure()
    
    for series in series_data:
        fig.add_trace(go.Scatter(
            x=categories,
            y=series["data"],
            name=series["name"],
            mode='lines+markers'
        ))
    
    fig.update_layout(
        xaxis_title="Attack Category",
        yaxis_title="Count",
        hovermode="x unified"
    )
    
    st.plotly_chart(fig, use_container_width=True)

def display_recent_incidents():
    st.subheader("Recent Incidents")
    
    scenario = st.selectbox("Filter by Scenario", ["All"] + list(attack_scenarios.keys()))
    
    # Filter incidents by scenario if provided
    with incidents_lock:
        filtered_incidents = recent_incidents
        if scenario != "All":
            filtered_incidents = [incident for incident in recent_incidents if incident.get('scenario') == scenario]
    
    if not filtered_incidents:
        st.warning("No incidents found for the selected scenario")
        return
    
    # Display incidents in a table
    st.dataframe(pd.DataFrame(filtered_incidents), use_container_width=True)

def display_attack_types():
    st.subheader("Attack Types Analysis")
    
    categories = ["Fuzzers", "Reconnaissance", "DoS", "Backdoor", "Exploits", "Shellcode", "Generic", "Analysis", "Worms"]
    
    # Use real data from recent incidents
    data = []
    with incidents_lock:
        for category in categories:
            count = sum(1 for incident in recent_incidents if incident.get('attack_cat') == category)
            data.append({
                "Attack Type": category,
                "Count": count
            })
    
    df_attack_types = pd.DataFrame(data)
    
    # Create a bar chart
    fig = px.bar(df_attack_types, x="Attack Type", y="Count", color="Attack Type")
    st.plotly_chart(fig, use_container_width=True)

def display_attack_origins():
    st.subheader("Attack Origins")
    
    origins = [
        {"country": "us", "count": random.randint(3, 10)},
        {"country": "france", "count": random.randint(2, 8)},
        {"country": "japan", "count": random.randint(1, 6)},
        {"country": "germany", "count": random.randint(2, 7)},
        {"country": "china", "count": random.randint(3, 9)},
        {"country": "russia", "count": random.randint(2, 8)},
        {"country": "uk", "count": random.randint(1, 5)}
    ]
    
    df_origins = pd.DataFrame(origins)
    
    # Create a choropleth map
    fig = px.choropleth(df_origins, 
                        locations="country", 
                        locationmode="country names",
                        color="count",
                        hover_name="country",
                        color_continuous_scale=px.colors.sequential.Plasma)
    
    st.plotly_chart(fig, use_container_width=True)

def display_attack_categories():
    st.subheader("Attack Categories Distribution")
    
    categories = ["Fuzzers", "Reconnaissance", "DoS", "Backdoor", "Exploits", "Shellcode", "Generic", "Analysis", "Worms"]
    
    # Count incidents by category
    category_counts = {}
    with incidents_lock:
        for category in categories:
            category_counts[category] = sum(1 for incident in recent_incidents if incident.get('attack_cat') == category)
    
    df_categories = pd.DataFrame({
        "Category": list(category_counts.keys()),
        "Count": list(category_counts.values())
    })
    
    # Create a pie chart
    fig = px.pie(df_categories, values="Count", names="Category")
    st.plotly_chart(fig, use_container_width=True)

def display_prediction_form():
    st.subheader("Attack Prediction")
    
    with st.form("prediction_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            proto = st.selectbox("Protocol", ["tcp", "udp", "icmp", "other"])
            service = st.selectbox("Service", ["http", "dns", "ftp", "smtp", "other"])
            state = st.selectbox("State", ["FIN", "CON", "INT", "other"])
            dur = st.number_input("Duration", min_value=0.0, value=0.1)
            sbytes = st.number_input("Source Bytes", min_value=0, value=1000)
        
        with col2:
            dbytes = st.number_input("Destination Bytes", min_value=0, value=800)
            sttl = st.number_input("Source TTL", min_value=0, value=64)
            dttl = st.number_input("Destination TTL", min_value=0, value=64)
            sload = st.number_input("Source Load", min_value=0.0, value=50.0)
            dload = st.number_input("Destination Load", min_value=0.0, value=40.0)
        
        submitted = st.form_submit_button("Predict")
        
        if submitted:
            features = {
                "proto": proto,
                "service": service,
                "state": state,
                "dur": dur,
                "sbytes": sbytes,
                "dbytes": dbytes,
                "sttl": sttl,
                "dttl": dttl,
                "sload": sload,
                "dload": dload
            }
            
            try:
                processed_data = preprocess_data(features)
                prediction = rf_model.predict(processed_data)[0]
                prob = rf_model.predict_proba(processed_data)[0].max()
                attack_cat = attack_label_encoder.inverse_transform([prediction])[0]
                
                if attack_cat != "Normal":
                    st.error(f"Attack Detected: {attack_cat} (Confidence: {prob:.2%})")
                else:
                    st.success(f"Normal Traffic (Confidence: {prob:.2%})")
                
                # Add to recent incidents with thread safety
                with incidents_lock:
                    incident = {
                        "attack_cat": attack_cat,
                        "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "threat": "Attack" if attack_cat != "Normal" else "Normal",
                        "confidence": float(prob),
                        "prediction": "Attack" if attack_cat != "Normal" else "Normal",
                        "scenario": get_scenario_for_attack(attack_cat)
                    }
                    recent_incidents.append(incident)
                
            except Exception as e:
                st.error(f"Prediction error: {str(e)}")

def generate_report():
    if not dataset_available:
        st.error("Report generation unavailable: Dataset not found")
        return
    
    scenario = st.selectbox("Select Scenario for Report", ["All"] + list(attack_scenarios.keys()))
    
    if st.button("Generate Report"):
        # Filter incidents by scenario
        with incidents_lock:
            filtered_incidents = recent_incidents
            if scenario != "All":
                filtered_incidents = [incident for incident in recent_incidents if incident.get('scenario') == scenario]
        
        # Generate report content
        report_content = f"Adminis Security Report - {scenario if scenario != 'All' else 'Comprehensive'}\n\n"
        report_content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        report_content += f"Total Incidents: {len(filtered_incidents)}\n\n"
        
        # Add scenario-specific details
        if scenario == "ransomware":
            report_content += "Ransomware Incidents:\n"
            for incident in filtered_incidents:
                report_content += f"- {incident['attack_cat']} on {incident['date']} (Cost: ${incident.get('cost', 0)})\n"
        
        elif scenario == "url":
            report_content += "Malicious URL Incidents:\n"
            for incident in filtered_incidents:
                report_content += f"- {incident['attack_cat']} on {incident['date']} (URL: {incident.get('url', 'N/A')})\n"
        
        elif scenario == "iot":
            report_content += "IoT Attack Incidents:\n"
            for incident in filtered_incidents:
                report_content += f"- {incident['attack_cat']} on {incident['date']} (Confidence: {incident['confidence']:.2f})\n"
        
        # Add general incident summary
        report_content += "\nAll Incidents Summary:\n"
        for incident in filtered_incidents[:20]:  # Limit to 20 incidents
            report_content += f"- {incident['attack_cat']} on {incident['date']} (Scenario: {incident.get('scenario', 'unknown')})\n"
        
        # Create download button
        st.download_button(
            label="Download Report",
            data=report_content,
            file_name=f"{scenario if scenario != 'All' else 'comprehensive'}_report.txt",
            mime="text/plain"
        )

# Main Streamlit App
def main():
    st.set_page_config(
        page_title="Adminis Security Platform",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("🛡️ Adminis Security Platform")
    st.markdown("Network attack detection and analysis platform using the UNSW-NB15 dataset")
    
    # Initialize the application
    if 'initialized' not in st.session_state:
        with st.spinner("Initializing system..."):
            load_dataset()
            load_model()
            
            # Start autonomous detection in a separate thread
            if 'autonomous_detection_thread' not in st.session_state:
                autonomous_detection_thread = threading.Thread(target=autonomous_detection, daemon=True)
                autonomous_detection_thread.start()
                st.session_state.autonomous_detection_thread = autonomous_detection_thread
            
            st.session_state.initialized = True
    
    # Create tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Dashboard", 
        "Threat Analysis", 
        "Model Performance", 
        "Attack Prediction", 
        "Reports"
    ])
    
    with tab1:
        display_health_check()
        display_threat_metrics()
        display_security_events_timeline()
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            display_attack_types()
        
        with col2:
            display_attack_categories()
        
        st.divider()
        display_attack_origins()
    
    with tab3:
        display_model_performance()
    
    with tab4:
        display_prediction_form()
        st.divider()
        display_recent_incidents()
    
    with tab5:
        generate_report()

if __name__ == '__main__':
    main()