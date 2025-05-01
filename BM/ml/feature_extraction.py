"""
Feature extraction for machine learning-based ransomware detection.
"""
import numpy as np
from collections import Counter
from datetime import datetime

def extract_process_features(process_history, file_operations, network_connections, pid):
    """Extract features from process history for ML detection"""
    features = {}
    
    # CPU usage features
    cpu_events = [e for e in process_history.get(pid, []) if e['type'] == 'cpu_usage']
    if cpu_events:
        cpu_values = [e['value'] for e in cpu_events]
        features['cpu_mean'] = np.mean(cpu_values) if cpu_values else 0
        features['cpu_max'] = np.max(cpu_values) if cpu_values else 0
        features['cpu_std'] = np.std(cpu_values) if cpu_values else 0
    else:
        features['cpu_mean'] = 0
        features['cpu_max'] = 0
        features['cpu_std'] = 0
    
    # Disk I/O features
    io_events = [e for e in process_history.get(pid, []) if e['type'] == 'disk_io']
    if io_events:
        read_bytes = [e.get('read_bytes', 0) for e in io_events]
        write_bytes = [e.get('write_bytes', 0) for e in io_events]
        features['io_read_mean'] = np.mean(read_bytes) if read_bytes else 0
        features['io_write_mean'] = np.mean(write_bytes) if write_bytes else 0
        features['io_read_max'] = np.max(read_bytes) if read_bytes else 0
        features['io_write_max'] = np.max(write_bytes) if write_bytes else 0
    else:
        features['io_read_mean'] = 0
        features['io_write_mean'] = 0
        features['io_read_max'] = 0
        features['io_write_max'] = 0
    
    # File operation features
    file_ops = file_operations.get(pid, [])
    op_types = [op['type'] for op in file_ops]
    op_counter = Counter(op_types)
    
    features['file_create_count'] = op_counter.get('create', 0)
    features['file_write_count'] = op_counter.get('write', 0)
    features['file_delete_count'] = op_counter.get('delete', 0)
    features['file_rename_count'] = op_counter.get('rename', 0)
    
    # Entropy features
    entropy_values = [op.get('entropy', 0) for op in file_ops if 'entropy' in op]
    features['mean_entropy'] = np.mean(entropy_values) if entropy_values else 0
    features['max_entropy'] = np.max(entropy_values) if entropy_values else 0
    
    # Network features
    net_connections = network_connections.get(pid, [])
    features['unique_ips'] = len(set(conn.get('remote_ip') for conn in net_connections 
                               if 'remote_ip' in conn))
    features['connection_count'] = len(net_connections)
    
    # Time-based features
    if file_ops:
        # Calculate operations per second
        times = [op['time'] for op in file_ops]
        if len(times) > 1:
            duration = max(times) - min(times)
            features['ops_per_second'] = len(times) / max(duration, 1)
        else:
            features['ops_per_second'] = 0
    else:
        features['ops_per_second'] = 0
    
    # Convert features to a flat list in a consistent order
    feature_vector = [
        features['cpu_mean'], 
        features['cpu_max'],
        features['cpu_std'],
        features['io_read_mean'],
        features['io_write_mean'],
        features['io_read_max'],
        features['io_write_max'],
        features['file_create_count'],
        features['file_write_count'],
        features['file_delete_count'],
        features['file_rename_count'],
        features['mean_entropy'],
        features['max_entropy'],
        features['unique_ips'],
        features['connection_count'],
        features['ops_per_second']
    ]
    
    return np.array(feature_vector)
