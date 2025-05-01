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
from sklearn.exceptions import NotFittedError

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
        self.is_model_fitted = False
        self.is_scaler_fitted = False
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
            # Create the data directory if it doesn't exist
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            if os.path.exists(model_path):
                try:
                    with open(model_path, 'rb') as f:
                        self.model = pickle.load(f)
                    logging.info(f"Loaded ML model from {model_path}")
                    self.is_model_fitted = True
                except Exception as e:
                    logging.warning(f"Failed to load model from {model_path}: {e}")
                    self.is_model_fitted = False
            else:
                logging.warning(f"ML model file not found at {model_path}")
                self.is_model_fitted = False
            
            if os.path.exists(scaler_path):
                try:
                    with open(scaler_path, 'rb') as f:
                        self.scaler = pickle.load(f)
                    logging.info(f"Loaded feature scaler from {scaler_path}")
                    self.is_scaler_fitted = True
                except Exception as e:
                    logging.warning(f"Failed to load scaler from {scaler_path}: {e}")
                    self.is_scaler_fitted = False
            else:
                logging.warning(f"Scaler file not found at {scaler_path}")
                self.is_scaler_fitted = False
                
            # If model is not loaded, create a default model
            if self.model is None:
                logging.info("Creating default anomaly detection model (unfitted)")
                self.model = IsolationForest(
                    n_estimators=100, 
                    contamination=0.1,
                    random_state=42
                )
                self.is_model_fitted = False
                
            # If scaler is not loaded, create a default scaler
            if self.scaler is None:
                logging.info("Creating default StandardScaler (unfitted)")
                self.scaler = StandardScaler()
                self.is_scaler_fitted = False

            # Create an empty sample dataset to fit the scaler if it's not fitted
            # This will allow predictions to continue with basic scaling
            if not self.is_scaler_fitted:
                logging.warning("Fitting scaler with dummy data to enable basic functionality")
                try:
                    # Create dummy features with same dimensions as our feature vector
                    dummy_features = np.zeros((5, len(self.feature_names)))
                    # Add some variety to avoid division by zero
                    for i in range(5):
                        dummy_features[i] = np.random.rand(len(self.feature_names))
                    self.scaler.fit(dummy_features)
                    self.is_scaler_fitted = True
                    logging.info("Scaler fitted with dummy data. Basic scaling enabled.")
                except Exception as e:
                    logging.error(f"Failed to fit scaler with dummy data: {e}")
                    self.is_scaler_fitted = False
                    
        except Exception as e:
            logging.error(f"Error loading ML model: {e}", exc_info=True)
            # Create default model on error
            self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            self.scaler = StandardScaler()
            self.is_model_fitted = False
            self.is_scaler_fitted = False
    
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
            self.scaler.fit(X)
            self.is_scaler_fitted = True
            X_scaled = self.scaler.transform(X)
            
            if y is not None:
                # If we have labels, use a supervised classifier
                self.model = RandomForestClassifier(n_estimators=100, random_state=42)
                self.model.fit(X_scaled, y)
                self.is_model_fitted = True
                logging.info("Trained supervised ML model")
            else:
                # Otherwise use anomaly detection
                self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
                self.model.fit(X_scaled)
                self.is_model_fitted = True
                logging.info("Trained unsupervised anomaly detection model")
            
            self.save_model()
        except Exception as e:
            logging.error(f"Error training ML model: {e}", exc_info=True)
            self.is_model_fitted = False
    
    def predict(self, X):
        """Predict if the sample is ransomware or not"""
        if self.model is None:
            logging.warning("Model not initialized for prediction")
            return 0
            
        # If model is not fitted, we can't make predictions
        if not self.is_model_fitted:
            if isinstance(self.model, IsolationForest):
                # With isolation forest, we can substitute a sensible default
                # since we can't actually predict
                logging.debug("Using default score for unfitted model")
                return 0  # Default score for unfitted model
            else:
                logging.warning("Skipping ML prediction: model not fitted")
                return 0
        
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        try:
            # Use scaler if it's fitted
            if self.is_scaler_fitted:
                try:
                    X_scaled = self.scaler.transform(X)
                except Exception as e:
                    logging.warning(f"Error applying scaler: {str(e)}. Using unscaled data.")
                    X_scaled = X
            else:
                logging.debug("Scaler not fitted. Using unscaled data.")
                X_scaled = X
            
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
        except NotFittedError:
            logging.warning("ML model or scaler not fitted. Returning default score.")
            return 0
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
