"""
Main script to start the Behavioral Monitor.

This module provides the command-line interface and main entry point
for the Behavioral Monitor system which detects malicious behavior.
"""

import os
import sys
import argparse
import logging
import time
from datetime import datetime

from ransomcare.behavior_monitor import BehaviorMonitor
from ransomcare.config import logger

def setup_arg_parser():
    """
    Set up command line argument parser.
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(description='Behavioral Monitor - Malicious Behavior Detection System')
    
    parser.add_argument('--no-file-monitor', action='store_true', 
                        help='Disable file system monitoring')
    parser.add_argument('--no-process-monitor', action='store_true',
                        help='Disable process monitoring')
    parser.add_argument('--log-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        default='INFO', help='Set the logging level')
    parser.add_argument('--log-file', type=str, 
                        help='Log file path (default: behavior_monitor_TIMESTAMP.log)')
    parser.add_argument('--paths', type=str, nargs='+',
                        help='Custom paths to monitor (overrides config.CRITICAL_SYSTEM_PATHS)')
    
    return parser

def configure_logging(args):
    """
    Configure logging settings based on command line arguments.
    
    Args:
        args: The parsed command line arguments
        
    Returns:
        str: Path to the log file
    """
    # Configure log level
    if args.log_level:
        numeric_level = getattr(logging, args.log_level.upper(), None)
        if isinstance(numeric_level, int):
            logger.setLevel(numeric_level)
            for handler in logger.handlers:
                handler.setLevel(numeric_level)
    
    # Set up custom log file if specified
    if args.log_file:
        log_path = args.log_file
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = f"behavior_monitor_{timestamp}.log"
    
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s'))
    file_handler.setLevel(logger.level)
    logger.addHandler(file_handler)
    
    return log_path

def configure_custom_paths(args):
    """
    Configure custom monitoring paths if provided.
    
    Args:
        args: The parsed command line arguments
    """
    if args.paths:
        from ransomcare.config import CRITICAL_SYSTEM_PATHS
        # This will only affect this instance, not the actual config file
        CRITICAL_SYSTEM_PATHS.clear()
        for path in args.paths:
            if os.path.exists(path) and os.path.isdir(path):
                CRITICAL_SYSTEM_PATHS.append(path)
                logger.info(f"Added custom monitoring path: {path}")
            else:
                logger.warning(f"Custom path doesn't exist or is not a directory: {path}")

def display_startup_banner(args, log_path):
    """
    Display a startup banner with monitor configuration.
    
    Args:
        args: The parsed command line arguments
        log_path: Path to the log file
    """
    print(f"""
╔══════════════════════════════════════════════════╗
║           Behavioral Monitor Started             ║
╠══════════════════════════════════════════════════╣
║ File Monitoring:    {'Enabled' if not args.no_file_monitor else 'Disabled'}                     ║
║ Process Monitoring: {'Enabled' if not args.no_process_monitor else 'Disabled'}                     ║
║ Log Level:          {args.log_level}                        ║
║ Log File:           {os.path.basename(log_path)}       ║
╚══════════════════════════════════════════════════╝

Press Ctrl+C to stop monitoring...
""")

def main():
    """
    Main function to parse args and start the monitor.
    
    This handles initialization, configuration, and the main execution loop.
    """
    parser = setup_arg_parser()
    args = parser.parse_args()
    
    # Configure logging based on arguments
    log_path = configure_logging(args)
    
    # Update custom paths if provided
    configure_custom_paths(args)
    
    # Initialize and start the behavior monitor
    logger.info("Initializing Behavior Monitor")
    monitor = BehaviorMonitor(
        enable_file_monitor=not args.no_file_monitor,
        enable_process_monitor=not args.no_process_monitor
    )
    
    try:
        # Start the monitoring
        monitor.start_monitoring()
        
        # Display startup banner
        display_startup_banner(args, log_path)
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down Behavior Monitor...")
        monitor.stop_monitoring()
        print("Shutdown complete.")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}", exc_info=True)
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()