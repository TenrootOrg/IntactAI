#!/usr/bin/env python3
"""
Workflow Logger - Centralized logging helper for automation workflows

This module provides a simple wrapper around add_log_to_run and update_run_status
to reduce boilerplate code in workflow services.

Usage:
    from services.workflow_logger import WorkflowLogger

    logger = WorkflowLogger(run_id, "AGENTIC")
    logger.info("Starting analysis")
    logger.progress(25, "Collecting artifacts")
    logger.success("Collection complete")
    logger.error("Failed to connect")
    logger.complete()  # Sets status to completed, progress to 100
    logger.fail("Connection timeout")  # Sets status to failed
"""

from services.workflow_service import add_log_to_run, update_run_status


class WorkflowLogger:
    """
    Helper class for logging workflow progress and status updates.

    Provides consistent logging format and reduces boilerplate code.
    """

    def __init__(self, run_id, prefix=""):
        """
        Initialize workflow logger.

        Args:
            run_id: Workflow run ID from create_automation_run()
            prefix: Optional prefix for console logs (e.g., "AGENTIC", "TIMESKETCH")
        """
        self.run_id = run_id
        self.prefix = f"[{prefix}]" if prefix else ""

    def info(self, message):
        """Log an info message."""
        add_log_to_run(self.run_id, message, "info")
        if self.prefix:
            print(f"{self.prefix} {message}", flush=True)

    def success(self, message):
        """Log a success message."""
        add_log_to_run(self.run_id, f"✓ {message}", "success")
        if self.prefix:
            print(f"{self.prefix} ✓ {message}", flush=True)

    def warning(self, message):
        """Log a warning message."""
        add_log_to_run(self.run_id, f"⚠ {message}", "warning")
        if self.prefix:
            print(f"{self.prefix} ⚠ {message}", flush=True)

    def error(self, message):
        """Log an error message."""
        add_log_to_run(self.run_id, f"✗ {message}", "error")
        if self.prefix:
            print(f"{self.prefix} ✗ {message}", flush=True)

    def progress(self, percent, message=None):
        """
        Update workflow progress.

        Args:
            percent: Progress percentage (0-100)
            message: Optional message to log with progress update
        """
        update_run_status(self.run_id, "running", progress=percent)
        if message:
            self.info(message)

    def complete(self, message=None):
        """
        Mark workflow as completed.

        Args:
            message: Optional completion message
        """
        if message:
            self.success(message)
        update_run_status(self.run_id, "completed", progress=100)

    def fail(self, message=None):
        """
        Mark workflow as failed.

        Args:
            message: Optional failure message
        """
        if message:
            self.error(message)
        update_run_status(self.run_id, "failed")


def create_logger(run_id, prefix=""):
    """
    Factory function to create a WorkflowLogger.

    Args:
        run_id: Workflow run ID
        prefix: Optional prefix for console logs

    Returns:
        WorkflowLogger instance
    """
    return WorkflowLogger(run_id, prefix)
