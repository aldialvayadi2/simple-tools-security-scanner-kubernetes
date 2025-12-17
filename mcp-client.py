import sys
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import time
from datetime import datetime
from mcp.server.fastmcp import FastMCP

# Default configuration
DEFAULT_SERVER = "http://127.0.0.1:8888"  # Default MCP Server URL
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests
MAX_RETRIES = 3  # Maximum number of retries for connection attempts

class CodeColors:
    # Basic CodeColors (for backward compatibility)
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # Core enhanced CodeColors
    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    ELECTRIC_PURPLE = '\033[38;5;129m'
    CYBER_ORANGE = '\033[38;5;208m'
    HACKER_RED = '\033[38;5;196m'
    TERMINAL_GRAY = '\033[38;5;240m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Enhanced reddish tones and highlighting CodeColors
    BLOOD_RED = '\033[38;5;124m'
    CRIMSON = '\033[38;5;160m'
    DARK_RED = '\033[38;5;88m'
    FIRE_RED = '\033[38;5;202m'
    ROSE_RED = '\033[38;5;167m'
    BURGUNDY = '\033[38;5;52m'
    SCARLET = '\033[38;5;197m'
    RUBY = '\033[38;5;161m'

    # Highlighting CodeColors
    HIGHLIGHT_RED = '\033[48;5;196m\033[38;5;15m'  # Red background, white text
    HIGHLIGHT_YELLOW = '\033[48;5;226m\033[38;5;16m'  # Yellow background, black text
    HIGHLIGHT_GREEN = '\033[48;5;46m\033[38;5;16m'  # Green background, black text
    HIGHLIGHT_BLUE = '\033[48;5;51m\033[38;5;16m'  # Blue background, black text
    HIGHLIGHT_PURPLE = '\033[48;5;129m\033[38;5;15m'  # Purple background, white text

    # Status CodeColors with reddish tones
    SUCCESS = '\033[38;5;46m'  # Bright green
    WARNING = '\033[38;5;208m'  # Orange
    ERROR = '\033[38;5;196m'  # Bright red
    CRITICAL = '\033[48;5;196m\033[38;5;15m\033[1m'  # Red background, white bold text
    INFO = '\033[38;5;51m'  # Cyan
    DEBUG = '\033[38;5;240m'  # Gray

    # Vulnerability severity CodeColors
    VULN_CRITICAL = '\033[48;5;124m\033[38;5;15m\033[1m'  # Dark red background
    VULN_HIGH = '\033[38;5;196m\033[1m'  # Bright red bold
    VULN_MEDIUM = '\033[38;5;208m\033[1m'  # Orange bold
    VULN_LOW = '\033[38;5;226m'  # Yellow
    VULN_INFO = '\033[38;5;51m'  # Cyan

    # Tool status CodeColors
    TOOL_RUNNING = '\033[38;5;46m\033[5m'  # Blinking green
    TOOL_SUCCESS = '\033[38;5;46m\033[1m'  # Bold green
    TOOL_FAILED = '\033[38;5;196m\033[1m'  # Bold red
    TOOL_TIMEOUT = '\033[38;5;208m\033[1m'  # Bold orange
    TOOL_RECOVERY = '\033[38;5;129m\033[1m'  # Bold purple

class ColoredFormatter(logging.Formatter):
    """Enhanced formatter with CodeColors and emojis for MCP client - matches server styling"""

    CodeColors = {
        'DEBUG': CodeColors.DEBUG,
        'INFO': CodeColors.SUCCESS,
        'WARNING': CodeColors.WARNING,
        'ERROR': CodeColors.ERROR,
        'CRITICAL': CodeColors.CRITICAL
    }

    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.CodeColors.get(record.levelname, CodeColors.BRIGHT_WHITE)

        # Add color and emoji to the message
        record.msg = f"{color}{emoji} {record.msg}{CodeColors.RESET}"
        return super().format(record)


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[🔥 Test MCP] %(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

# Apply colored formatter
for handler in logging.getLogger().handlers:
    handler.setFormatter(ColoredFormatter(
        "[🔥 AI MCP] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))


logger = logging.getLogger(__name__)

class MCPClient:
    """Enhanced client for communicating with the AI API Server"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the AI Client

        Args:
            server_url: URL of the AI API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

        # Try to connect to server with retries
        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"🔗 Attempting to connect to  AI API at {server_url} (attempt {i+1}/{MAX_RETRIES})")
                # First try a direct connection test before using the health endpoint
                try:
                    test_response = self.session.get(f"{self.server_url}/health", timeout=5)
                    test_response.raise_for_status()
                    health_check = test_response.json()
                    connected = True
                    logger.info(f"🎯 Successfully connected to AI API Server at {server_url}")
                    logger.info(f"🏥 Server health status: {health_check.get('status', 'unknown')}")
                    logger.info(f"📊 Server version: {health_check.get('version', 'unknown')}")
                    break
                except requests.exceptions.ConnectionError:
                    logger.warning(f"🔌 Connection refused to {server_url}. Make sure the AI server is running.")
                    time.sleep(2)  # Wait before retrying
                except Exception as e:
                    logger.warning(f"⚠️  Connection test failed: {str(e)}")
                    time.sleep(2)  # Wait before retrying
            except Exception as e:
                logger.warning(f"❌ Connection attempt {i+1} failed: {str(e)}")
                time.sleep(2)  # Wait before retrying

        if not connected:
            error_msg = f"Failed to establish connection to AI API Server at {server_url} after {MAX_RETRIES} attempts"
            logger.error(error_msg)
            # We'll continue anyway to allow the MCP server to start, but tools will likely fail

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.

        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters

        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"📡 GET {url} with params: {params}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.

        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send

        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"📡 POST {url} with data: {json_data}")
            response = self.session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute a generic command on the server

        Args:
            command: Command to execute
            use_cache: Whether to use caching for this command

        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command, "use_cache": use_cache})

    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the AI API Server

        Returns:
            Health status information
        """
        return self.safe_get("health")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the AI MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_SERVER,
                      help=f"AI API server URL (default: {DEFAULT_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def setup_mcp_server(mcp_client: MCPClient) -> FastMCP:
    """
    Set up the MCP server with all enhanced tool functions

    Args:
        mcp_client: Initialized MCPClient

    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("ai-mcp")

    # ============================================================================
    # CORE NETWORK SCANNING TOOLS
    # ============================================================================

    @mcp.tool()
    def trivy_scan(scan_type: str = "image", target: str = "", output_format: str = "json", severity: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Trivy for container and filesystem vulnerability scanning.

        Args:
            scan_type: Type of scan (image, fs, repo, config)
            target: Target to scan (image name, directory, repository)
            output_format: Output format (json, table, sarif)
            severity: Severity filter (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)
            output_file: File to save results
            additional_args: Additional Trivy arguments

        Returns:
            Vulnerability scan results
        """
        data = {
            "scan_type": scan_type,
            "target": target,
            "output_format": output_format,
            "severity": severity,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Trivy {scan_type} scan: {target}")
        result = mcp_client.safe_post("api/tools/scan/trivy", data)
        if result.get("success"):
            logger.info(f"✅ Trivy scan completed for {target}")
        else:
            logger.error(f"❌ Trivy scan failed for {target}")
        return result

    @mcp.tool()
    def kubescape_scan(scan_type: str = "framework", target: str = "", namespace: str = "", output_format: str = "json",additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Kubescape for Kubernetes security assessment.

        Args:
            scan_type: Type of scan (framework, workload, image)
            target: Target to scan (framework name, workload location, image name)
            namespace: Namespace to scan (default, kube-system, etc)
            additional_args: Additional Kubescape arguments
            output_format: Format for output result

        Returns:
            Vulnerability scan results
        """
        data = {
            "scan_type": scan_type,
            "target": target,
            "namespace": namespace,
            "additional_args": additional_args,
            "output_format": output_format
        }
        logger.info(f"🔍 Starting Kubescape {scan_type} scan: {target}")
        result = mcp_client.safe_post("api/tools/scan/kubescape", data)
        if result.get("success"):
            logger.info(f"✅ Kubescape scan completed for {target}")
        else:
            logger.error(f"❌ Kubescape scan failed for {target}")
        return result

    @mcp.tool()
    def audit_popeye(namespace: str = "default", output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Popeye for Kubernetes security audit.

        Args:
            namespace: Namespace to scan (default, kube-system, etc)
            output_format: Output format (json, text, etc)
            additional_args: Additional Popeye arguments

        Returns:
            Vulnerability scan results
        """

        data = {
            "namespace": namespace,
            "output_format": output_format,
            "additional_args": additional_args
        }

        logger.info(f"{CodeColors.FIRE_RED}🔍 Initiating Popeye auditing namespace: {namespace}{CodeColors.RESET}")

        # Use enhanced error handling by default
        data["use_recovery"] = True
        result = mcp_client.safe_post("api/tools/audit/popeye", data)

        if result.get("success"):
            logger.info(f"{CodeColors.SUCCESS}✅ Popeye auditing completed successfully for namespace {namespace}{CodeColors.RESET}")

            # Check for recovery information
            if result.get("recovery_info", {}).get("recovery_applied"):
                recovery_info = result["recovery_info"]
                attempts = recovery_info.get("attempts_made", 1)
                logger.info(f"{CodeColors.HIGHLIGHT_YELLOW} Recovery applied: {attempts} attempts made {CodeColors.RESET}")
        else:
            logger.error(f"{CodeColors.ERROR}❌ Popeye auditing failed for {namespace}{CodeColors.RESET}")

            # Check for human escalation
            if result.get("human_escalation"):
                logger.error(f"{CodeColors.CRITICAL} HUMAN ESCALATION REQUIRED {CodeColors.RESET}")

        return result

    @mcp.tool()
    def kube_bench_cis(config_dir: str = "",
                      output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute kube-bench for CIS Kubernetes benchmark checks.

        Args:
            version: Kubernetes version
            config_dir: Configuration directory
            output_format: Output format (json, yaml)
            additional_args: Additional kube-bench arguments

        Returns:
            CIS Kubernetes benchmark results
        """
        data = {
            "config_dir": config_dir,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting kube-bench CIS benchmark")
        result = mcp_client.safe_post("api/tools/audit/kube-bench", data)
        if result.get("success"):
            logger.info(f"✅ kube-bench benchmark completed")
        else:
            logger.error(f"❌ kube-bench benchmark failed")
        return result      

    @mcp.tool()
    def falco_runtime_monitoring(config_file: str = "",
                                rules_file: str = "", output_format: str = "json",
                                duration: int = 60, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Falco for runtime security monitoring.

        Args:
            config_file: Falco configuration file
            rules_file: Custom rules file
            output_format: Output format (json, text)
            duration: Monitoring duration in seconds
            additional_args: Additional Falco arguments

        Returns:
            Runtime security monitoring results
        """
        data = {
            "config_file": config_file,
            "rules_file": rules_file,
            "output_format": output_format,
            "duration": duration,
            "additional_args": additional_args
        }
        logger.info(f"🛡️  Starting Falco runtime monitoring for {duration}s")
        result = mcp_client.safe_post("api/tools/monitoring/falco", data)
        if result.get("success"):
            logger.info(f"✅ Falco monitoring completed")
        else:
            logger.error(f"❌ Falco monitoring failed")
        return result
    
    @mcp.tool()
    def rbac_tool_analyze(command: str = "",
                        output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Analyze Kubernetes RBAC permissions using rbac-tool.

        Args:
            command: Command for rbac-tool to do (analysis, lookup, show, etc).
            output_format: Output format (json, yaml, text).
            additional_args: Additional RBAC Tools Arguments.
            
        Returns:
            RBAC analysis result containing roles, bindings, and privilege risks.
        """
        data = {
            "command": command,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"🔐 Running RBAC-Tool analysis on {command}")
        result = mcp_client.safe_post("api/tools/scan/rbac-tool", data)

        if result.get("success"):
            logger.info("✅ RBAC-Tool analysis completed")
        else:
            logger.error("❌ RBAC-Tool analysis failed")
        return result

    @mcp.tool()
    def kubesec_scan_manifest(manifest_path: str = "",
                            output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Scan a Kubernetes manifest using KubeSec.

        Args:
            manifest_path: Path to the Kubernetes YAML/JSON manifest.
            output_format: Output format (json, text).
            additional_args: Additional Kubesec Arguments.
            
        Returns:
            KubeSec security risk assessment.
        """
        data = {
            "manifest_path": manifest_path,
            "output_format": output_format,
            "additional_args": additional_args
        }

        logger.info(f"🔎 Running KubeSec security scan on {manifest_path}")
        result = mcp_client.safe_post("api/tools/scan/kubesec", data)

        if result.get("success"):
            logger.info("✅ KubeSec scan completed")
        else:
            logger.error("❌ KubeSec scan failed")
        return result


    # ============================================================================
    # File Management
    # ============================================================================

    @mcp.tool()
    def list_files(directory: str = ".") -> Dict[str, Any]:
        """
        List files in a directory on the server.

        Args:
            directory: Directory to list (relative to server's base directory)

        Returns:
            Directory listing results
        """
        logger.info(f"📂 Listing files in directory: {directory}")
        result = mcp_client.safe_get("api/files/list", {"directory": directory})
        if result.get("success"):
            file_count = len(result.get("files", []))
            logger.info(f"✅ Listed {file_count} files in {directory}")
        else:
            logger.error(f"❌ Failed to list files in {directory}")
        return result

    # ============================================================================
    # SYSTEM MONITORING & TELEMETRY
    # ============================================================================

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the AI server.

        Returns:
            Server health information with tool availability and telemetry
        """
        logger.info(f"🏥 Checking AI server health")
        result = mcp_client.check_health()
        if result.get("status") == "healthy":
            logger.info(f"✅ Server is healthy - {result.get('total_tools_available', 0)} tools available")
        else:
            logger.warning(f"⚠️  Server health check returned: {result.get('status', 'unknown')}")
        return result

    @mcp.tool()
    def get_cache_stats() -> Dict[str, Any]:
        """
        Get cache statistics from the AI server.

        Returns:
            Cache performance statistics
        """
        logger.info(f"💾 Getting cache statistics")
        result = MCPClient.safe_get("api/cache/stats")
        if "hit_rate" in result:
            logger.info(f"📊 Cache hit rate: {result.get('hit_rate', 'unknown')}")
        return result

    @mcp.tool()
    def clear_cache() -> Dict[str, Any]:
        """
        Clear the cache on the AI server.

        Returns:
            Cache clear operation results
        """
        logger.info(f"🧹 Clearing server cache")
        result = mcp_client.safe_post("api/cache/clear", {})
        if result.get("success"):
            logger.info(f"✅ Cache cleared successfully")
        else:
            logger.error(f"❌ Failed to clear cache")
        return result

    @mcp.tool()
    def get_telemetry() -> Dict[str, Any]:
        """
        Get system telemetry from the AI server.

        Returns:
            System performance and usage telemetry
        """
        logger.info(f"📈 Getting system telemetry")
        result = MCPClient.safe_get("api/telemetry")
        if "commands_executed" in result:
            logger.info(f"📊 Commands executed: {result.get('commands_executed', 0)}")
        return result

    # ============================================================================
    # PROCESS MANAGEMENT TOOLS (v5.0 ENHANCEMENT)
    # ============================================================================

    @mcp.tool()
    def list_active_processes() -> Dict[str, Any]:
        """
        List all active processes on the AI server.

        Returns:
            List of active processes with their status and progress
        """
        logger.info("📊 Listing active processes")
        result = mcp_client.safe_get("api/processes/list")
        if result.get("success"):
            logger.info(f"✅ Found {result.get('total_count', 0)} active processes")
        else:
            logger.error("❌ Failed to list processes")
        return result

    @mcp.tool()
    def get_process_status(pid: int) -> Dict[str, Any]:
        """
        Get the status of a specific process.

        Args:
            pid: Process ID to check

        Returns:
            Process status information including progress and runtime
        """
        logger.info(f"🔍 Checking status of process {pid}")
        result = mcp_client.safe_get(f"api/processes/status/{pid}")
        if result.get("success"):
            logger.info(f"✅ Process {pid} status retrieved")
        else:
            logger.error(f"❌ Process {pid} not found or error occurred")
        return result

    @mcp.tool()
    def terminate_process(pid: int) -> Dict[str, Any]:
        """
        Terminate a specific running process.

        Args:
            pid: Process ID to terminate

        Returns:
            Success status of the termination operation
        """
        logger.info(f"🛑 Terminating process {pid}")
        result = mcp_client.safe_post(f"api/processes/terminate/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} terminated successfully")
        else:
            logger.error(f"❌ Failed to terminate process {pid}")
        return result

    @mcp.tool()
    def pause_process(pid: int) -> Dict[str, Any]:
        """
        Pause a specific running process.

        Args:
            pid: Process ID to pause

        Returns:
            Success status of the pause operation
        """
        logger.info(f"⏸️ Pausing process {pid}")
        result = mcp_client.safe_post(f"api/processes/pause/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} paused successfully")
        else:
            logger.error(f"❌ Failed to pause process {pid}")
        return result

    @mcp.tool()
    def resume_process(pid: int) -> Dict[str, Any]:
        """
        Resume a paused process.

        Args:
            pid: Process ID to resume

        Returns:
            Success status of the resume operation
        """
        logger.info(f"▶️ Resuming process {pid}")
        result = mcp_client.safe_post(f"api/processes/resume/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} resumed successfully")
        else:
            logger.error(f"❌ Failed to resume process {pid}")
        return result

    @mcp.tool()
    def get_process_dashboard() -> Dict[str, Any]:
        """
        Get enhanced process dashboard with visual status indicators.

        Returns:
            Real-time dashboard with progress bars, system metrics, and process status
        """
        logger.info("📊 Getting process dashboard")
        result = mcp_client.safe_get("api/processes/dashboard")
        if result.get("success", True) and "total_processes" in result:
            total = result.get("total_processes", 0)
            logger.info(f"✅ Dashboard retrieved: {total} active processes")

            # Log visual summary for better UX
            if total > 0:
                logger.info("📈 Active Processes Summary:")
                for proc in result.get("processes", [])[:3]:  # Show first 3
                    logger.info(f"   ├─ PID {proc['pid']}: {proc['progress_bar']} {proc['progress_percent']}")
        else:
            logger.error("❌ Failed to get process dashboard")
        return result

    @mcp.tool()
    def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the server with enhanced logging.

        Args:
            command: The command to execute
            use_cache: Whether to use caching for this command

        Returns:
            Command execution results with enhanced telemetry
        """
        try:
            logger.info(f"⚡ Executing command: {command}")
            result = mcp_client.execute_command(command, use_cache)
            if "error" in result:
                logger.error(f"❌ Command failed: {result['error']}")
                return {
                    "success": False,
                    "error": result["error"],
                    "stdout": "",
                    "stderr": f"Error executing command: {result['error']}"
                }

            if result.get("success"):
                execution_time = result.get("execution_time", 0)
                logger.info(f"✅ Command completed successfully in {execution_time:.2f}s")
            else:
                logger.warning(f"⚠️  Command completed with errors")

            return result
        except Exception as e:
            logger.error(f"💥 Error executing command '{command}': {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": f"Error executing command: {str(e)}"
            }

    # ============================================================================
    # ADVANCED VULNERABILITY INTELLIGENCE MCP TOOLS (v1.0 ENHANCEMENT)
    # ============================================================================

    @mcp.tool()
    def monitor_cve_feeds(hours: int = 24, severity_filter: str = "HIGH,CRITICAL", keywords: str = "") -> Dict[str, Any]:
        """
        Monitor CVE databases for new vulnerabilities with AI analysis.

        Args:
            hours: Hours to look back for new CVEs (default: 24)
            severity_filter: Filter by CVSS severity - comma-separated values (LOW,MEDIUM,HIGH,CRITICAL,ALL)
            keywords: Filter CVEs by keywords in description (comma-separated)

        Returns:
            Latest CVEs with exploitability analysis and threat intelligence

        Example:
            monitor_cve_feeds(48, "CRITICAL", "remote code execution")
        """
        data = {
            "hours": hours,
            "severity_filter": severity_filter,
            "keywords": keywords
        }
        logger.info(f"🔍 Monitoring CVE feeds for last {hours} hours | Severity: {severity_filter}")
        result = mcp_client.safe_post("api/vuln-intel/cve-monitor", data)

        if result.get("success"):
            cve_count = len(result.get("cve_monitoring", {}).get("cves", []))
            exploit_analysis_count = len(result.get("exploitability_analysis", []))
            logger.info(f"✅ Found {cve_count} CVEs with {exploit_analysis_count} exploitability analyses")

        return result

    # ============================================================================
    # ENHANCED VISUAL OUTPUT TOOLS
    # ============================================================================

    @mcp.tool()
    def get_live_dashboard() -> Dict[str, Any]:
        """
        Get a beautiful live dashboard showing all active processes with enhanced visual formatting.

        Returns:
            Live dashboard with visual process monitoring and system metrics
        """
        logger.info("📊 Fetching live process dashboard")
        result = MCPClient.safe_get("api/processes/dashboard")
        if result.get("success", True):
            logger.info("✅ Live dashboard retrieved successfully")
        else:
            logger.error("❌ Failed to retrieve live dashboard")
        return result

    @mcp.tool()
    def create_vulnerability_report(vulnerabilities: str, target: str = "", scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Create a beautiful vulnerability report with severity-based styling and visual indicators.

        Args:
            vulnerabilities: JSON string containing vulnerability data
            target: Target that was scanned
            scan_type: Type of scan performed

        Returns:
            Formatted vulnerability report with visual enhancements
        """
        import json

        try:
            # Parse vulnerabilities if provided as JSON string
            if isinstance(vulnerabilities, str):
                vuln_data = json.loads(vulnerabilities)
            else:
                vuln_data = vulnerabilities

            logger.info(f"📋 Creating vulnerability report for {len(vuln_data)} findings")

            # Create individual vulnerability cards
            vulnerability_cards = []
            for vuln in vuln_data:
                card_result = MCPClient.safe_post("api/visual/vulnerability-card", vuln)
                if card_result.get("success"):
                    vulnerability_cards.append(card_result.get("vulnerability_card", ""))

            # Create summary report
            summary_data = {
                "target": target,
                "vulnerabilities": vuln_data,
                "tools_used": [scan_type],
                "execution_time": 0
            }

            summary_result = MCPClient.safe_post("api/visual/summary-report", summary_data)

            logger.info("✅ Vulnerability report created successfully")
            return {
                "success": True,
                "vulnerability_cards": vulnerability_cards,
                "summary_report": summary_result.get("summary_report", ""),
                "total_vulnerabilities": len(vuln_data),
                "timestamp": summary_result.get("timestamp", "")
            }

        except Exception as e:
            logger.error(f"❌ Failed to create vulnerability report: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def format_tool_output_visual(tool_name: str, output: str, success: bool = True) -> Dict[str, Any]:
        """
        Format tool output with beautiful visual styling, syntax highlighting, and structure.

        Args:
            tool_name: Name of the security tool
            output: Raw output from the tool
            success: Whether the tool execution was successful

        Returns:
            Beautifully formatted tool output with visual enhancements
        """
        logger.info(f"🎨 Formatting output for {tool_name}")

        data = {
            "tool": tool_name,
            "output": output,
            "success": success
        }

        result = MCPClient.safe_post("api/visual/tool-output", data)
        if result.get("success"):
            logger.info(f"✅ Tool output formatted successfully for {tool_name}")
        else:
            logger.error(f"❌ Failed to format tool output for {tool_name}")

        return result

    @mcp.tool()
    def create_scan_summary(target: str, tools_used: str, vulnerabilities_found: int = 0,
                           execution_time: float = 0.0, findings: str = "") -> Dict[str, Any]:
        """
        Create a comprehensive scan summary report with beautiful visual formatting.

        Args:
            target: Target that was scanned
            tools_used: Comma-separated list of tools used
            vulnerabilities_found: Number of vulnerabilities discovered
            execution_time: Total execution time in seconds
            findings: Additional findings or notes

        Returns:
            Beautiful scan summary report with visual enhancements
        """
        logger.info(f"📊 Creating scan summary for {target}")

        tools_list = [tool.strip() for tool in tools_used.split(",")]

        summary_data = {
            "target": target,
            "tools_used": tools_list,
            "execution_time": execution_time,
            "vulnerabilities": [{"severity": "info"}] * vulnerabilities_found,  # Mock data for count
            "findings": findings
        }

        result = MCPClient.safe_post("api/visual/summary-report", summary_data)
        if result.get("success"):
            logger.info("✅ Scan summary created successfully")
        else:
            logger.error("❌ Failed to create scan summary")

        return result
    
    @mcp.tool()
    def display_system_metrics() -> Dict[str, Any]:
        """
        Display current system metrics and performance indicators with visual formatting.

        Returns:
            System metrics with beautiful visual presentation
        """
        logger.info("📈 Fetching system metrics")

        # Get telemetry data
        telemetry_result = MCPClient.safe_get("api/telemetry")

        if telemetry_result.get("success", True):
            logger.info("✅ System metrics retrieved successfully")

            # Format the metrics for better display
            metrics = telemetry_result.get("system_metrics", {})
            stats = {
                "cpu_percent": metrics.get("cpu_percent", 0),
                "memory_percent": metrics.get("memory_percent", 0),
                "disk_usage": metrics.get("disk_usage", 0),
                "uptime_seconds": telemetry_result.get("uptime_seconds", 0),
                "commands_executed": telemetry_result.get("commands_executed", 0),
                "success_rate": telemetry_result.get("success_rate", "0%")
            }

            return {
                "success": True,
                "metrics": stats,
                "formatted_display": f"""
🖥️  System Performance Metrics:
├─ CPU Usage: {stats['cpu_percent']:.1f}%
├─ Memory Usage: {stats['memory_percent']:.1f}%
├─ Disk Usage: {stats['disk_usage']:.1f}%
├─ Uptime: {stats['uptime_seconds']:.0f}s
├─ Commands Executed: {stats['commands_executed']}
└─ Success Rate: {stats['success_rate']}
""",
                "timestamp": telemetry_result.get("timestamp", "")
            }
        else:
            logger.error("❌ Failed to retrieve system metrics")
            return telemetry_result

    # ============================================================================
    # INTELLIGENT DECISION ENGINE TOOLS
    # ============================================================================

    @mcp.tool()
    def analyze_target_intelligence(target: str) -> Dict[str, Any]:
        """
        Analyze target using AI-powered intelligence to create comprehensive profile.

        Args:
            target: Target URL, IP address, or domain to analyze

        Returns:
            Comprehensive target profile with technology detection, risk assessment, and recommendations
        """
        logger.info(f"🧠 Analyzing target intelligence for: {target}")

        data = {"target": target}
        result = MCPClient.safe_post("api/intelligence/analyze-target", data)

        if result.get("success"):
            profile = result.get("target_profile", {})
            logger.info(f"✅ Target analysis completed - Type: {profile.get('target_type')}, Risk: {profile.get('risk_level')}")
        else:
            logger.error(f"❌ Target analysis failed for {target}")

        return result

    @mcp.tool()
    def select_optimal_tools_ai(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """
        Use AI to select optimal security tools based on target analysis and testing objective.

        Args:
            target: Target to analyze
            objective: Testing objective - "comprehensive", "quick", or "stealth"

        Returns:
            AI-selected optimal tools with effectiveness ratings and target profile
        """
        logger.info(f"🎯 Selecting optimal tools for {target} with objective: {objective}")

        data = {
            "target": target,
            "objective": objective
        }
        result = MCPClient.safe_post("api/intelligence/select-tools", data)

        if result.get("success"):
            tools = result.get("selected_tools", [])
            logger.info(f"✅ AI selected {len(tools)} optimal tools: {', '.join(tools[:3])}{'...' if len(tools) > 3 else ''}")
        else:
            logger.error(f"❌ Tool selection failed for {target}")

        return result

    @mcp.tool()
    def optimize_tool_parameters_ai(target: str, tool: str, context: str = "{}") -> Dict[str, Any]:
        """
        Use AI to optimize tool parameters based on target profile and context.

        Args:
            target: Target to test
            tool: Security tool to optimize
            context: JSON string with additional context (stealth, aggressive, etc.)

        Returns:
            AI-optimized parameters for maximum effectiveness
        """
        import json

        logger.info(f"⚙️  Optimizing parameters for {tool} against {target}")

        try:
            context_dict = json.loads(context) if context != "{}" else {}
        except:
            context_dict = {}

        data = {
            "target": target,
            "tool": tool,
            "context": context_dict
        }
        result = MCPClient.safe_post("api/intelligence/optimize-parameters", data)

        if result.get("success"):
            params = result.get("optimized_parameters", {})
            logger.info(f"✅ Parameters optimized for {tool} - {len(params)} parameters configured")
        else:
            logger.error(f"❌ Parameter optimization failed for {tool}")

        return result

    @mcp.tool()
    def error_handling_statistics() -> Dict[str, Any]:
        """
        Get intelligent error handling system statistics and recent error patterns.

        Returns:
            Error handling statistics and patterns
        """
        logger.info(f"{CodeColors.ELECTRIC_PURPLE}📊 Retrieving error handling statistics{CodeColors.RESET}")
        result = MCPClient.safe_get("api/error-handling/statistics")

        if result.get("success"):
            stats = result.get("statistics", {})
            total_errors = stats.get("total_errors", 0)
            recent_errors = stats.get("recent_errors_count", 0)

            logger.info(f"{CodeColors.SUCCESS}✅ Error statistics retrieved{CodeColors.RESET}")
            logger.info(f"  📈 Total Errors: {total_errors}")
            logger.info(f"  🕒 Recent Errors: {recent_errors}")

            # Log error breakdown by type
            error_counts = stats.get("error_counts_by_type", {})
            if error_counts:
                logger.info(f"{CodeColors.HIGHLIGHT_BLUE} ERROR BREAKDOWN {CodeColors.RESET}")
                for error_type, count in error_counts.items():
                                          logger.info(f"  {CodeColors.FIRE_RED}{error_type}: {count}{CodeColors.RESET}")
        else:
            logger.error(f"{CodeColors.ERROR}❌ Failed to retrieve error statistics{CodeColors.RESET}")

        return result

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the AI MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_SERVER,
                      help=f"AI API server URL (default: {DEFAULT_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    """Main entry point for the MCP server."""
    args = parse_args()

    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled")

    # MCP compatibility: No banner output to avoid JSON parsing issues
    logger.info(f"🚀 Starting AI MCP Client v1.0")
    logger.info(f"🔗 Connecting to: {args.server}")

    try:
        # Initialize the AI client
        mcp_client = MCPClient(args.server, args.timeout)

        # Check server health and log the result
        health = mcp_client.check_health()
        if "error" in health:
            logger.warning(f"⚠️  Unable to connect to AI API server at {args.server}: {health['error']}")
            logger.warning("🚀 MCP server will start, but tool execution may fail")
        else:
            logger.info(f"🎯 Successfully connected to AI API server at {args.server}")
            logger.info(f"🏥 Server health status: {health['status']}")
            logger.info(f"📊 Version: {health.get('version', 'unknown')}")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"❌ Missing tools: {', '.join(missing_tools[:15])}{'...' if len(missing_tools) > 15 else ''}")

        # Set up and run the MCP server
        mcp = setup_mcp_server(mcp_client)
        logger.info("🚀 Starting AI MCP server")
        logger.info("🤖 Ready to serve AI agents with security capabilities")
        mcp.run()
    except Exception as e:
        logger.error(f"💥 Error starting MCP server: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()