"""
Machine learning model for ransomware detection.
"""
import os
import logging
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn import metrics

from .feature_extraction import extract_process_features

# Default location for storing and loading the model
MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'ml_model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'scaler.pkl')

class RansomwareDetectionModel:
    """Machine learning model for ransomware detection"""
    
    def __init__(self):
        """Initialize the detection model"""
        self.model = None
        self.scaler = None
        self.feature_names = [
            'cpu_mean', 'cpu_max', 'cpu_std', 
            'io_read_mean', 'io_write_mean', 'io_read_max', 'io_write_max',
            'file_create_count', 'file_write_count', 'file_delete_count', 'file_rename_count',
            'mean_entropy', 'max_entropy', 'unique_ips', 'connection_count', 'ops_per_second'
        ]
        self.load_model()
    
    def load_model(self, model_path=None, scaler_path=None):
        """Load the pre-trained model if it exists"""
        model_path = model_path or MODEL_PATH
        scaler_path = scaler_path or SCALER_PATH
        
        try:
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logging.info(f"Loaded ML model from {model_path}")
            
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logging.info(f"Loaded feature scaler from {scaler_path}")
                
            if self.model is None:
                # Create a default model if none exists
                logging.info("Creating default anomaly detection model")
                self.model = IsolationForest(
                    n_estimators=100, 
                    contamination=0.1,  # Assume 10% anomalies
                    random_state=42
                )
                
            if self.scaler is None:
                self.scaler = StandardScaler()
        except Exception as e:
            logging.error(f"Error loading ML model: {e}")
            # Create default model on error
            self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            self.scaler = StandardScaler()
    
    def save_model(self, model_path=None, scaler_path=None):
        """Save the trained model"""
        if self.model is None:
            logging.warning("No model to save")
            return
        
        model_path = model_path or MODEL_PATH
        scaler_path = scaler_path or SCALER_PATH
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
            logging.info(f"Saved ML model to {model_path}")
            
            if self.scaler is not None:
                with open(scaler_path, 'wb') as f:
                    pickle.dump(self.scaler, f)
                logging.info(f"Saved feature scaler to {scaler_path}")
        except Exception as e:
            logging.error(f"Error saving ML model: {e}")
    
    def train(self, X, y=None):
        """Train the model with labeled data if available, or use anomaly detection"""
        if len(X) == 0:
            logging.warning("No training data provided")
            return
        
        try:
            # Fit the scaler
            X_scaled = self.scaler.fit_transform(X)
            
            if y is not None:
                # If we have labels, use a supervised classifier
                self.model = RandomForestClassifier(n_estimators=100, random_state=42)
                self.model.fit(X_scaled, y)
                logging.info("Trained supervised ML model")
            else:
                # Otherwise use anomaly detection
                self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
                self.model.fit(X_scaled)
                logging.info("Trained unsupervised anomaly detection model")
            
            self.save_model()
        except Exception as e:
            logging.error(f"Error training ML model: {e}")
    
    def predict(self, X):
        """Predict if the sample is ransomware or not"""
        if self.model is None:
            logging.warning("Model not initialized for prediction")
            return 0
        
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        try:
            X_scaled = self.scaler.transform(X) if self.scaler is not None else X
            
            if isinstance(self.model, IsolationForest):
                # For anomaly detection: -1 is anomaly, 1 is normal
                # We need to convert it to a score where higher means more anomalous
                scores = self.model.decision_function(X_scaled)
                # Convert to a score between 0-10 where higher means more suspicious
                anomaly_scores = 10 * (1 - (scores + 1) / 2)
                return anomaly_scores[0]
            else:
                # For supervised learning, use probability of ransomware class
                probs = self.model.predict_proba(X_scaled)
                # Assuming the ransomware class is at index 1
                ransomware_prob = probs[0][1] if probs.shape[1] > 1 else 0
                # Convert to a score between 0-10
                score = 10 * ransomware_prob
                return score
        except Exception as e:
            logging.error(f"Error predicting with ML model: {e}")
            return 0
    
    def detect_ransomware(self, process_history, file_operations, network_connections, pid):
        """Extract features for a process and detect if it's ransomware"""
        try:
            features = extract_process_features(
                process_history, file_operations, network_connections, pid
            )
            score = self.predict(features)
            # Return a score between 0-10
            return min(10, max(0, score))
        except Exception as e:
            logging.error(f"Error in ML ransomware detection: {e}")
            return 0
