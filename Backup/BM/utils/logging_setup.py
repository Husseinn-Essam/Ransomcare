"""Logging configuration for the ransomware detector"""

import logging

def setup_logging():
    """Configure logging with rotation and console output"""
    # Configure logging with rotation
    logging.basicConfig(
        filename='ransomware_detector.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Add console handler for immediate feedback
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    return logging.getLogger(__name__)
