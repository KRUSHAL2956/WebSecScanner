"""
Centralized logging configuration for WebSec Scanner
"""
import logging
import sys
from pathlib import Path

def setup_logging(log_level=logging.INFO):
    """
    Configure logging for the application
    
    Args:
        log_level: Logging level (default: INFO)
    """
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            # Console handler
            logging.StreamHandler(sys.stdout),
            # File handler
            logging.FileHandler(log_dir / 'websec_scanner.log')
        ]
    )
    
    # Set specific log levels for noisy libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)

def get_logger(name):
    """
    Get a logger instance for a module
    
    Args:
        name: Module name (usually __name__)
    
    Returns:
        logging.Logger: Configured logger instance
    """
    return logging.getLogger(name)
