"""
Machine learning based ransomware detector.
"""
import logging
from ..utils import is_process_trusted, get_process_name
from ..ml import RansomwareDetectionModel

# Global references to be set from main
process_history = {}        # Will be replaced with global reference
file_operations = {}        # Will be replaced with global reference
network_connections = {}    # Will be replaced with global reference
ml_model = None             # Will be initialized in setup_ml_detector

def setup_ml_detector():
    """Initialize the ML detector"""
    global ml_model
    try:
        ml_model = RansomwareDetectionModel()
        logging.info("ML detector initialized")
        return ml_model
    except Exception as e:
        logging.error(f"Error initializing ML detector: {e}")
        return None

def detect_ransomware_ml(pid):
    """Use machine learning to detect ransomware"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    if ml_model is None:
        setup_ml_detector()
        if ml_model is None:
            return 0
    
    try:
        # Check if we have enough data
        if (pid not in process_history or len(process_history[pid]) < 5) and \
           (pid not in file_operations or len(file_operations[pid]) < 5):
            # Not enough data to make a reliable ML prediction
            return 0
        
        # Get the ML score from our model
        score = ml_model.detect_ransomware(
            process_history, file_operations, network_connections, pid
        )
        
        # Convert the ML score (0-10) to our scoring system
        # A moderate ML score (5+) gives 3 points
        # A high ML score (8+) gives 5 points
        if score >= 8:
            return 5
        elif score >= 5:
            return 3
        elif score >= 3:
            return 1
        return 0
    except Exception as e:
        logging.error(f"Error in ML ransomware detection for PID {pid}: {e}")
        return 0
