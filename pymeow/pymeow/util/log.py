"""
Logging utilities for WhatsApp.

Port of whatsmeow/util/log/
"""
import logging
from typing import Optional

class Logger:
    """WhatsApp logger with subloggers."""

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.debug_logs = True

    def sub_logger(self, suffix: str) -> 'Logger':
        """Create a sublogger with the given suffix."""
        return Logger(f"{self.logger.name}.{suffix}")

    def debug(self, msg: str, *args, **kwargs) -> None:
        """Log a debug message."""
        if self.debug_logs:
            self.logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs) -> None:
        """Log an info message."""
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        """Log a warning message."""
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        """Log an error message."""
        self.logger.error(msg, *args, **kwargs)
