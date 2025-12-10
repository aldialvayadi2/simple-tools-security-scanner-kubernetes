import traceback
import time
import subprocess
import threading
from utils.visualEngine import ModernVisualEngine
from typing import Dict, Any
from datetime import datetime
from utils.logger import logger
from utils.processTermination import ProcessManager
from utils.errorHandling import RecoveryAction, ErrorContext, ErrorType
from utils.globalVar import COMMAND_TIMEOUT
from utils.globalInstance import telemetry, cache, error_handler

class EnhancedCommandExecutor:
    """Enhanced command executor with caching, progress tracking, and better output handling"""

    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
        self.start_time = None
        self.end_time = None

    def _read_stdout(self):
        """Thread function to continuously read and display stdout"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.stdout_data += line
                    # Real-time output display
                    logger.info(f"📤 STDOUT: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stdout: {e}")

    def _read_stderr(self):
        """Thread function to continuously read and display stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.stderr_data += line
                    # Real-time error output display
                    logger.warning(f"📥 STDERR: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")

    def _show_progress(self, duration: float):
        """Show enhanced progress indication for long-running commands"""
        if duration > 2:  # Show progress for commands taking more than 2 seconds
            progress_chars = ModernVisualEngine.PROGRESS_STYLES['dots']
            start = time.time()
            i = 0
            while self.process and self.process.poll() is None:
                elapsed = time.time() - start
                char = progress_chars[i % len(progress_chars)]

                # Calculate progress percentage (rough estimate)
                progress_percent = min((elapsed / self.timeout) * 100, 99.9)
                progress_fraction = progress_percent / 100

                # Calculate ETA
                eta = 0
                if progress_percent > 5:  # Only show ETA after 5% progress
                    eta = ((elapsed / progress_percent) * 100) - elapsed

                # Calculate speed
                bytes_processed = len(self.stdout_data) + len(self.stderr_data)
                speed = f"{bytes_processed/elapsed:.0f} B/s" if elapsed > 0 else "0 B/s"

                # Update process manager with progress
                ProcessManager.update_process_progress(
                    self.process.pid,
                    progress_fraction,
                    f"Running for {elapsed:.1f}s",
                    bytes_processed
                )

                # Create beautiful progress bar using ModernVisualEngine
                progress_bar = ModernVisualEngine.render_progress_bar(
                    progress_fraction,
                    width=30,
                    style='cyber',
                    label=f"⚡ PROGRESS {char}",
                    eta=eta,
                    speed=speed
                )

                logger.info(f"{progress_bar} | {elapsed:.1f}s | PID: {self.process.pid}")
                time.sleep(0.8)
                i += 1
                if elapsed > self.timeout:
                    break

    def execute(self) -> Dict[str, Any]:
        """Execute the command with enhanced monitoring and output"""
        self.start_time = time.time()

        logger.info(f"🚀 EXECUTING: {self.command}")
        logger.info(f"⏱️  TIMEOUT: {self.timeout}s | PID: Starting...")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            pid = self.process.pid
            logger.info(f"🆔 PROCESS: PID {pid} started")

            # Register process with ProcessManager (v5.0 enhancement)
            ProcessManager.register_process(pid, self.command, self.process)

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Start progress tracking in a separate thread
            progress_thread = threading.Thread(target=self._show_progress, args=(self.timeout,))
            progress_thread.daemon = True
            progress_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.end_time = time.time()

                # Process completed, join the threads
                self.stdout_thread.join(timeout=1)
                self.stderr_thread.join(timeout=1)

                execution_time = self.end_time - self.start_time

                # Cleanup process from registry (v5.0 enhancement)
                ProcessManager.cleanup_process(pid)

                if self.return_code == 0:
                    logger.info(f"✅ SUCCESS: Command completed | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(True, execution_time)
                else:
                    logger.warning(f"⚠️  WARNING: Command completed with errors | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(False, execution_time)

            except subprocess.TimeoutExpired:
                self.end_time = time.time()
                execution_time = self.end_time - self.start_time

                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"⏰ TIMEOUT: Command timed out after {self.timeout}s | Terminating PID {self.process.pid}")

                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.error(f"🔪 FORCE KILL: Process {self.process.pid} not responding to termination")
                    self.process.kill()

                self.return_code = -1
                telemetry.record_execution(False, execution_time)

            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)

            # Log enhanced final results with summary using ModernVisualEngine
            output_size = len(self.stdout_data) + len(self.stderr_data)
            execution_time = self.end_time - self.start_time if self.end_time else 0

            # Create status summary
            status_icon = "✅" if success else "❌"
            status_color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if success else ModernVisualEngine.COLORS['HACKER_RED']
            timeout_status = f" {ModernVisualEngine.COLORS['WARNING']}[TIMEOUT]{ModernVisualEngine.COLORS['RESET']}" if self.timed_out else ""

            # Create beautiful results summary
            results_summary = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📊 FINAL RESULTS {status_icon}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Command:{ModernVisualEngine.COLORS['RESET']} {self.command[:55]}{'...' if len(self.command) > 55 else ''}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}⏱️  Duration:{ModernVisualEngine.COLORS['RESET']} {execution_time:.2f}s{timeout_status}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}📊 Output Size:{ModernVisualEngine.COLORS['RESET']} {output_size} bytes
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🔢 Exit Code:{ModernVisualEngine.COLORS['RESET']} {self.return_code}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📈 Status:{ModernVisualEngine.COLORS['RESET']} {'SUCCESS' if success else 'FAILED'} | Cached: Yes
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""

            # Log the beautiful summary
            for line in results_summary.strip().split('\n'):
                if line.strip():
                    logger.info(line)

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
                "execution_time": self.end_time - self.start_time if self.end_time else 0,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            self.end_time = time.time()
            execution_time = self.end_time - self.start_time if self.start_time else 0

            logger.error(f"💥 ERROR: Command execution failed: {str(e)}")
            logger.error(f"🔍 TRACEBACK: {traceback.format_exc()}")
            telemetry.record_execution(False, execution_time)

            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }

def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Execute a shell command with enhanced features

    Args:
        command: The command to execute
        use_cache: Whether to use caching for this command

    Returns:
        A dictionary containing the stdout, stderr, return code, and metadata
    """

    # Check cache first
    if use_cache:
        cached_result = cache.get(command, {})
        if cached_result:
            return cached_result

    # Execute command
    executor = EnhancedCommandExecutor(command)
    result = executor.execute()

    # Cache successful results
    if use_cache and result.get("success", False):
        cache.set(command, {}, result)

    return result

def execute_command_with_recovery(tool_name: str, command: str, parameters: Dict[str, Any] = None,
                                 use_cache: bool = True, max_attempts: int = 3) -> Dict[str, Any]:
    """
    Execute a command with intelligent error handling and recovery

    Args:
        tool_name: Name of the tool being executed
        command: The command to execute
        parameters: Tool parameters for context
        use_cache: Whether to use caching
        max_attempts: Maximum number of recovery attempts

    Returns:
        A dictionary containing execution results with recovery information
    """
    if parameters is None:
        parameters = {}

    attempt_count = 0
    last_error = None
    recovery_history = []

    while attempt_count < max_attempts:
        attempt_count += 1

        try:
            # Execute the command
            result = execute_command(command, use_cache)

            # Check if execution was successful
            if result.get("success", False):
                # Add recovery information to successful result
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": len(recovery_history) > 0,
                    "recovery_history": recovery_history
                }
                return result

            # Command failed, determine if we should attempt recovery
            error_message = result.get("stderr", "Unknown error")
            exception = Exception(error_message)

            # Create context for error handler
            context = {
                "target": parameters.get("target", "unknown"),
                "parameters": parameters,
                "attempt_count": attempt_count,
                "command": command
            }

            # Get recovery strategy from error handler
            recovery_strategy = error_handler.handle_tool_failure(tool_name, exception, context)
            recovery_history.append({
                "attempt": attempt_count,
                "error": error_message,
                "recovery_action": recovery_strategy.action.value,
                "timestamp": datetime.now().isoformat()
            })

            # Apply recovery strategy
            if recovery_strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
                delay = recovery_strategy.parameters.get("initial_delay", 5)
                backoff = recovery_strategy.parameters.get("max_delay", 60)
                actual_delay = min(delay * (recovery_strategy.backoff_multiplier ** (attempt_count - 1)), backoff)

                retry_info = f'Retrying in {actual_delay}s (attempt {attempt_count}/{max_attempts})'
                logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', retry_info)}")
                time.sleep(actual_delay)
                continue

            elif recovery_strategy.action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE:
                # Adjust parameters to reduce scope
                adjusted_params = error_handler.auto_adjust_parameters(
                    tool_name,
                    error_handler.classify_error(error_message, exception),
                    parameters
                )

                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with reduced scope")
                continue

            elif recovery_strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
                # Get alternative tool
                alternative_tool = error_handler.get_alternative_tool(tool_name, recovery_strategy.parameters)

                if alternative_tool:
                    switch_info = f'Switching to alternative: {alternative_tool}'
                    logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', switch_info)}")
                    # This would require the calling function to handle tool switching
                    result["alternative_tool_suggested"] = alternative_tool
                    result["recovery_info"] = {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "tool_switch_suggested"
                    }
                    return result
                else:
                    logger.warning(f"⚠️  No alternative tool found for {tool_name}")

            elif recovery_strategy.action == RecoveryAction.ADJUST_PARAMETERS:
                # Adjust parameters based on error type
                error_type = error_handler.classify_error(error_message, exception)
                adjusted_params = error_handler.auto_adjust_parameters(tool_name, error_type, parameters)

                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with adjusted parameters")
                continue

            elif recovery_strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
                # Create error context for escalation
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=error_handler.classify_error(error_message, exception),
                    error_message=error_message,
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace="",
                    system_resources=error_handler._get_system_resources()
                )

                escalation_data = error_handler.escalate_to_human(
                    error_context,
                    recovery_strategy.parameters.get("urgency", "medium")
                )

                result["human_escalation"] = escalation_data
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "human_escalation"
                }
                return result

            elif recovery_strategy.action == RecoveryAction.ABORT_OPERATION:
                logger.error(f"🛑 Aborting {tool_name} operation after {attempt_count} attempts")
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "operation_aborted"
                }
                return result

            last_error = exception

        except Exception as e:
            last_error = e
            logger.error(f"💥 Unexpected error in recovery attempt {attempt_count}: {str(e)}")

            # If this is the last attempt, escalate to human
            if attempt_count >= max_attempts:
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=ErrorType.UNKNOWN,
                    error_message=str(e),
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace=traceback.format_exc(),
                    system_resources=error_handler._get_system_resources()
                )

                escalation_data = error_handler.escalate_to_human(error_context, "high")

                return {
                    "success": False,
                    "error": str(e),
                    "human_escalation": escalation_data,
                    "recovery_info": {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "human_escalation_after_failure"
                    }
                }

    # All attempts exhausted
    logger.error(f"🚫 All recovery attempts exhausted for {tool_name}")
    return {
        "success": False,
        "error": f"All recovery attempts exhausted: {str(last_error)}",
        "recovery_info": {
            "attempts_made": attempt_count,
            "recovery_applied": True,
            "recovery_history": recovery_history,
            "final_action": "all_attempts_exhausted"
        }
    }

def _rebuild_command_with_params(tool_name: str, original_command: str, new_params: Dict[str, Any]) -> str:
    """Rebuild command with new parameters"""
    # This is a simplified implementation - in practice, you'd need tool-specific logic
    # For now, we'll just append new parameters
    additional_args = []

    for key, value in new_params.items():
        if key == "timeout" and tool_name in ["nmap", "gobuster", "nuclei"]:
            additional_args.append(f"--timeout {value}")
        elif key == "threads" and tool_name in ["gobuster", "feroxbuster", "ffuf"]:
            additional_args.append(f"-t {value}")
        elif key == "delay" and tool_name in ["gobuster", "feroxbuster"]:
            additional_args.append(f"--delay {value}")
        elif key == "timing" and tool_name == "nmap":
            additional_args.append(f"{value}")
        elif key == "concurrency" and tool_name == "nuclei":
            additional_args.append(f"-c {value}")
        elif key == "rate-limit" and tool_name == "nuclei":
            additional_args.append(f"-rl {value}")

    if additional_args:
        return f"{original_command} {' '.join(additional_args)}"

    return original_command
