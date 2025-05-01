"""
Entry point for running the module directly.
"""
import sys
import logging
import traceback
from .main import start_monitoring

if __name__ == "__main__":
    try:
        print("=" * 60)
        print("     RansomCare - Ransomware Detection System      ")
        print("=" * 60)
        
        # Setup logging
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler("ransomcare.log"),
                logging.StreamHandler()
            ]
        )
        
        # Log startup information
        logging.info("RansomCare starting up")
        print("[+] Starting monitoring services...")
        
        # Start the monitoring system
        start_monitoring() # This function now blocks until shutdown
        
        logging.info("RansomCare main process exiting normally.")
        print("[+] RansomCare finished.")
        sys.exit(0) # Explicit exit after start_monitoring returns
        
    except KeyboardInterrupt:
        # This might be redundant if start_monitoring handles it, but safe to keep
        print("\n[*] RansomCare shutdown requested by user (main entry).")
        logging.info("RansomCare shutdown requested by user (main entry).")
        # Ensure stop_event is set if start_monitoring didn't catch it
        # (Requires stop_event to be accessible here, might need refactoring)
        # if 'stop_event' in locals() or 'stop_event' in globals():
        #    stop_event.set()
        sys.exit(0)
    except Exception as e:
        error_msg = f"Critical error during startup or main execution: {str(e)}"
        logging.critical(error_msg, exc_info=True) # Log traceback for critical errors
        # logging.debug(traceback.format_exc()) # Redundant if exc_info=True
        print(f"\n[!!!] CRITICAL ERROR: {error_msg}")
        print("[!!!] Check ransomcare.log for detailed traceback.")
        sys.exit(1)
