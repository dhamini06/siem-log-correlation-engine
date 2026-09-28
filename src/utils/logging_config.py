"""Structured logging configuration for SIEM Lab."""

import logging
import sys
import os
from logging.handlers import RotatingFileHandler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")

DEFAULT_LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def setup_logging(log_level: str = "INFO", log_to_stdout: bool = True, log_to_file: bool = True) -> logging.Logger:
    """Set up structured logging for the application.

    Args:
        log_level: One of DEBUG, INFO, WARNING, ERROR, CRITICAL
        log_to_stdout: Whether to log to stdout
        log_to_file: Whether to log to ./logs/app.log

    Returns:
        Configured logger instance
    """
    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Avoid adding handlers if already configured
    if root_logger.handlers:
        return root_logger

    # Console handler (stdout)
    if log_to_stdout:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        console_formatter = logging.Formatter(DEFAULT_LOG_FORMAT, DATE_FORMAT)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # File handler
    if log_to_file:
        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5)
        file_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        file_formatter = logging.Formatter(DEFAULT_LOG_FORMAT, DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("elasticsearch").setLevel(logging.WARNING)

    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized - level: {log_level}, file: {LOG_FILE if log_to_file else 'disabled'}")
    return logger