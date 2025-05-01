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
        start_monitoring()
        
    except KeyboardInterrupt:
        print("\n[*] RansomCare shutdown requested by user")
        logging.info("RansomCare shutdown requested by user")
        sys.exit(0)
    except Exception as e:
        error_msg = f"Critical error during startup: {str(e)}"
        logging.critical(error_msg)
        logging.debug(traceback.format_exc())
        print(f"\n[!] {error_msg}")
        print("[!] Check ransomcare.log for more details")
        sys.exit(1)
