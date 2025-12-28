"""
Comprehensive logging configuration for Agentic-IAM

Supports multiple handlers (console, file, structured logging)
with JSON output for production environments.
"""
import logging
import logging.handlers
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
import traceback


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add extra fields if present
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info)
            }
        
        return json.dumps(log_data)


class PlainFormatter(logging.Formatter):
    """Plain text formatter for human-readable logs"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as plain text"""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname
        logger = record.name
        message = record.getMessage()
        
        base_format = f"[{timestamp}] [{level:8}] {logger}: {message}"
        
        if record.exc_info:
            base_format += f"\n{traceback.format_exc()}"
        
        return base_format


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_format: str = "plain",
    enable_console: bool = True,
    max_file_size: int = 104857600,  # 100MB
    backup_count: int = 10
) -> None:
    """
    Configure logging for the application
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (None = no file logging)
        log_format: Log format (json or plain)
        enable_console: Enable console logging
        max_file_size: Maximum log file size in bytes
        backup_count: Number of backup log files to keep
    """
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Create formatter
    if log_format.lower() == "json":
        formatter = JSONFormatter()
    else:
        formatter = PlainFormatter()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level.upper()))
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.LoggerAdapter:
    """
    Get a logger instance with context support
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        LoggerAdapter instance
    """
    logger = logging.getLogger(name)
    return logger


class StructuredLogger:
    """Wrapper for structured logging with context"""
    
    def __init__(self, logger: logging.Logger):
        """Initialize with a logger instance"""
        self.logger = logger
        self.context = {}
    
    def set_context(self, **kwargs) -> None:
        """Set logging context"""
        self.context.update(kwargs)
    
    def clear_context(self) -> None:
        """Clear logging context"""
        self.context.clear()
    
    def _log(self, level: int, message: str, **extra) -> None:
        """Internal logging method"""
        extra.update(self.context)
        self.logger.log(level, message, extra=extra)
    
    def debug(self, message: str, **extra) -> None:
        """Log debug message"""
        self._log(logging.DEBUG, message, **extra)
    
    def info(self, message: str, **extra) -> None:
        """Log info message"""
        self._log(logging.INFO, message, **extra)
    
    def warning(self, message: str, **extra) -> None:
        """Log warning message"""
        self._log(logging.WARNING, message, **extra)
    
    def error(self, message: str, **extra) -> None:
        """Log error message"""
        self._log(logging.ERROR, message, **extra)
    
    def critical(self, message: str, **extra) -> None:
        """Log critical message"""
        self._log(logging.CRITICAL, message, **extra)


# Module-level setup
if __name__ == "__main__":
    # Test logging configuration
    setup_logging(
        log_level="DEBUG",
        log_file="test.log",
        log_format="json",
        enable_console=True
    )
    
    logger = get_logger(__name__)
    logger.info("Logging configured successfully")
    logger.debug("Debug message", extra={"key": "value"})
    logger.error("Error message")
