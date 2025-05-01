"""
Detection modules for identifying ransomware activity.
"""

from .file_operations import (
    detect_file_encryption_patterns,
    detect_multiple_extension_changes,
    detect_mass_file_operations,
    detect_suspicious_file_access,
    detect_ransomware_extensions,
    detect_high_entropy_writes
)

from .process_activity import (
    detect_ransomware_process_patterns,
    detect_high_disk_usage
)

from .network_activity import detect_network_c2_traffic

from .system_changes import (
    detect_shadow_copy_deletion,
    detect_system_modifications
)

__all__ = [
    'detect_file_encryption_patterns',
    'detect_multiple_extension_changes',
    'detect_mass_file_operations',
    'detect_suspicious_file_access',
    'detect_ransomware_extensions',
    'detect_high_entropy_writes',
    'detect_ransomware_process_patterns',
    'detect_high_disk_usage',
    'detect_network_c2_traffic',
    'detect_shadow_copy_deletion',
    'detect_system_modifications'
]
