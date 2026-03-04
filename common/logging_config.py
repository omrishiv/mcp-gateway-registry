"""Shared logging configuration for all MCP Gateway Registry services.

Provides a consistent logging format and setup across all services.
"""

import logging


LOG_FORMAT: str = (
    "%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s"
)


def configure_logging(
    level: int = logging.INFO,
) -> None:
    """Configure logging with the standard format used across all services.

    Args:
        level: Logging level (default: logging.INFO)
    """
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
    )


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name.

    Convenience wrapper around logging.getLogger().

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)
