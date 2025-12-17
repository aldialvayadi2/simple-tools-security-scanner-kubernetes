import argparse
import logging
import traceback
import time
from datetime import datetime
import psutil
import uvicorn
from utils.visualEngine import ModernVisualEngine
from utils.commandManagement import *
from utils.logger import logger
from utils.globalVar import *
from utils.globalInstance import *

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

# API Configuration
app = FastAPI()

@app.route("/health", methods=["GET"])
async def health_check(request: Request):
    """Health check endpoint with comprehensive tool detection"""

    audit_tools = ["kube-bench", "popeye"]
    scan_tools = [ "trivy", "kubescape", "rbac-tool", "kubesec"]
    monitor_tools = ["falco"]

    all_tools = (
        audit_tools + scan_tools + monitor_tools
    )
    tools_status = {}

    for tool in all_tools:
        try:
            result = execute_command(f"which {tool}", use_cache=True)
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    category_stats = {
        "audit": {"total": len(audit_tools), "available": sum(1 for tool in audit_tools if tools_status.get(tool, False))},
        "scan": {"total": len(scan_tools), "available": sum(1 for tool in scan_tools if tools_status.get(tool, False))},
        "monitor": {"total": len(monitor_tools), "available": sum(1 for tool in monitor_tools if tools_status.get(tool, False))},
    }

    return JSONResponse({
        "status": "healthy",
        "message": "AI Tools API Server is operational",
        "version": "1.0.0",
        "tools_status": tools_status,
        "total_tools_available": sum(1 for tool, available in tools_status.items() if available),
        "total_tools_count": len(all_tools),
        "category_stats": category_stats,
        "cache_stats": cache.get_stats(),
        "telemetry": telemetry.get_stats(),
        "uptime": time.time() - telemetry.stats["start_time"]
    })

@app.route("/api/command", methods=["POST"])
async def generic_command(request: Request):
    """Execute any command provided in the request with enhanced logging"""
    try:
        params = await request.json()
        command = params.get("command", "")
        use_cache = params.get("use_cache", True)

        if not command:
            logger.warning("⚠️  Command endpoint called without command parameter")
            raise HTTPException(status_code=400, detail="Command parameter is required")
            
        result = execute_command(command, use_cache=use_cache)
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"💥 Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

# File Operations API Endpoints
@app.route("/api/files/list", methods=["GET"])
async def list_files(request: Request):
    """List files in a directory"""
    try:
        params = await request.json()
        directory = params.get("directory", ".")
        result = file_manager.list_files(directory)
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"💥 Error listing files: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

# Cache Management Endpoint
@app.route("/api/cache/stats", methods=["GET"])
async def cache_stats():
    """Get cache statistics"""
    return JSONResponse(cache.get_stats())

@app.route("/api/cache/clear", methods=["POST"])
async def clear_cache():
    """Clear the cache"""
    cache.cache.clear()
    cache.stats = {"hits": 0, "misses": 0, "evictions": 0}
    logger.info("🧹 Cache cleared")
    return JSONResponse({"success": True, "message": "Cache cleared"})

@app.route("/api/telemetry", methods=["GET"])
async def get_telemetry():
    """Get system telemetry"""
    return JSONResponse(telemetry.get_stats())


# ============================================================================
# PROCESS MANAGEMENT API ENDPOINTS (v5.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/processes/list", methods=["GET"])
async def list_processes():
    """List all active processes"""
    try:
        processes = ProcessManager.list_active_processes()

        # Add calculated fields for each process
        for pid, info in processes.items():
            runtime = time.time() - info["start_time"]
            info["runtime_formatted"] = f"{runtime:.1f}s"

            if info["progress"] > 0:
                eta = (runtime / info["progress"]) * (1.0 - info["progress"])
                info["eta_formatted"] = f"{eta:.1f}s"
            else:
                info["eta_formatted"] = "Unknown"

        return JSONResponse({
            "success": True,
            "active_processes": processes,
            "total_count": len(processes)
        })
    except Exception as e:
        logger.error(f"💥 Error listing processes: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/status/<int:pid>", methods=["GET"])
async def get_process_status(pid):
    """Get status of a specific process"""
    try:
        process_info = ProcessManager.get_process_status(pid)

        if process_info:
            # Add calculated fields
            runtime = time.time() - process_info["start_time"]
            process_info["runtime_formatted"] = f"{runtime:.1f}s"

            if process_info["progress"] > 0:
                eta = (runtime / process_info["progress"]) * (1.0 - process_info["progress"])
                process_info["eta_formatted"] = f"{eta:.1f}s"
            else:
                process_info["eta_formatted"] = "Unknown"

            return JSONResponse({
                "success": True,
                "process": process_info
            })
        else:
            return JSONResponse({
                "success": False,
                "error": f"Process {pid} not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error getting process status: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/terminate/<int:pid>", methods=["POST"])
async def terminate_process(pid):
    """Terminate a specific process"""
    try:
        success = ProcessManager.terminate_process(pid)

        if success:
            logger.info(f"🛑 Process {pid} terminated successfully")
            return JSONResponse({
                "success": True,
                "message": f"Process {pid} terminated successfully"
            })
        else:
            return JSONResponse({
                "success": False,
                "error": f"Failed to terminate process {pid} or process not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error terminating process {pid}: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/pause/<int:pid>", methods=["POST"])
async def pause_process(pid):
    """Pause a specific process"""
    try:
        success = ProcessManager.pause_process(pid)

        if success:
            logger.info(f"⏸️ Process {pid} paused successfully")
            return JSONResponse({
                "success": True,
                "message": f"Process {pid} paused successfully"
            })
        else:
            return JSONResponse({
                "success": False,
                "error": f"Failed to pause process {pid} or process not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error pausing process {pid}: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/resume/<int:pid>", methods=["POST"])
async def resume_process(pid):
    """Resume a paused process"""
    try:
        success = ProcessManager.resume_process(pid)

        if success:
            logger.info(f"▶️ Process {pid} resumed successfully")
            return JSONResponse({
                "success": True,
                "message": f"Process {pid} resumed successfully"
            })
        else:
            return JSONResponse({
                "success": False,
                "error": f"Failed to resume process {pid} or process not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error resuming process {pid}: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/dashboard", methods=["GET"])
async def process_dashboard():
    """Get enhanced process dashboard with visual status using ModernVisualEngine"""
    try:
        processes = ProcessManager.list_active_processes()
        current_time = time.time()

        # Create beautiful dashboard using ModernVisualEngine
        dashboard_visual = ModernVisualEngine.create_live_dashboard(processes)

        dashboard = {
            "timestamp": datetime.now().isoformat(),
            "total_processes": len(processes),
            "visual_dashboard": dashboard_visual,
            "processes": [],
            "system_load": {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "active_connections": len(psutil.net_connections())
            }
        }

        for pid, info in processes.items():
            runtime = current_time - info["start_time"]
            progress_fraction = info.get("progress", 0)

            # Create beautiful progress bar using ModernVisualEngine
            progress_bar = ModernVisualEngine.render_progress_bar(
                progress_fraction,
                width=25,
                style='cyber',
                eta=info.get("eta", 0)
            )

            process_status = {
                "pid": pid,
                "command": info["command"][:60] + "..." if len(info["command"]) > 60 else info["command"],
                "status": info["status"],
                "runtime": f"{runtime:.1f}s",
                "progress_percent": f"{progress_fraction * 100:.1f}%",
                "progress_bar": progress_bar,
                "eta": f"{info.get('eta', 0):.0f}s" if info.get('eta', 0) > 0 else "Calculating...",
                "bytes_processed": info.get("bytes_processed", 0),
                "last_output": info.get("last_output", "")[:100]
            }
            dashboard["processes"].append(process_status)

        return JSONResponse(dashboard)

    except Exception as e:
        logger.error(f"💥 Error getting process dashboard: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/visual/vulnerability-card", methods=["POST"])
async def create_vulnerability_card(request: Request):
    """Create a beautiful vulnerability card using ModernVisualEngine"""
    try:
        data = await request.json()
        if not data:
            return JSONResponse({"error": "No data provided"}), 400

        # Create vulnerability card
        card = ModernVisualEngine.render_vulnerability_card(data)

        return JSONResponse({
            "success": True,
            "vulnerability_card": card,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating vulnerability card: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/visual/summary-report", methods=["POST"])
async def create_summary_report(request: Request):
    """Create a beautiful summary report using ModernVisualEngine"""
    try:
        data = await request.json()
        if not data:
            return JSONResponse({"error": "No data provided"}), 400

        # Create summary report
        visual_engine = ModernVisualEngine()
        report = visual_engine.create_summary_report(data)

        return JSONResponse({
            "success": True,
            "summary_report": report,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating summary report: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/visual/tool-output", methods=["POST"])
async def format_tool_output(request: Request):
    """Format tool output using ModernVisualEngine"""
    try:
        data = await request.json()
        if not data or 'tool' not in data or 'output' not in data:
            return JSONResponse({"error": "Tool and output data required"}), 400

        tool = data['tool']
        output = data['output']
        success = data.get('success', True)

        # Format tool output
        formatted_output = ModernVisualEngine.format_tool_output(tool, output, success)

        return JSONResponse({
            "success": True,
            "formatted_output": formatted_output,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error formatting tool output: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# ADVANCED VULNERABILITY INTELLIGENCE API ENDPOINTS (v6.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/vuln-intel/cve-monitor", methods=["POST"])
async def cve_monitor(request: Request):
    """Monitor CVE databases for new vulnerabilities with AI analysis"""
    try:
        params = await request.json()
        hours = params.get("hours", 24)
        severity_filter = params.get("severity_filter", "HIGH,CRITICAL")
        keywords = params.get("keywords", "")

        logger.info(f"🔍 Monitoring CVE feeds for last {hours} hours with severity filter: {severity_filter}")

        # Fetch latest CVEs
        cve_results = cve_intelligence.fetch_latest_cves(hours, severity_filter)

        # Filter by keywords if provided
        if keywords and cve_results.get("success"):
            keyword_list = [k.strip().lower() for k in keywords.split(",")]
            filtered_cves = []

            for cve in cve_results.get("cves", []):
                description = cve.get("description", "").lower()
                if any(keyword in description for keyword in keyword_list):
                    filtered_cves.append(cve)

            cve_results["cves"] = filtered_cves
            cve_results["filtered_by_keywords"] = keywords
            cve_results["total_after_filter"] = len(filtered_cves)

        # Analyze exploitability for top CVEs
        exploitability_analysis = []
        for cve in cve_results.get("cves", [])[:5]:  # Analyze top 5 CVEs
            cve_id = cve.get("cve_id", "")
            if cve_id:
                analysis = cve_intelligence.analyze_cve_exploitability(cve_id)
                if analysis.get("success"):
                    exploitability_analysis.append(analysis)

        result = {
            "success": True,
            "cve_monitoring": cve_results,
            "exploitability_analysis": exploitability_analysis,
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"📊 CVE monitoring completed | Found: {len(cve_results.get('cves', []))} CVEs")
        return JSONResponse(result)

    except Exception as e:
        logger.error(f"💥 Error in CVE monitoring: {str(e)}")
        return JSONResponse({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500


# ============================================================================
# INTELLIGENT DECISION ENGINE API ENDPOINTS
# ============================================================================

@app.route("/api/intelligence/analyze-target", methods=["POST"])
async def analyze_target(request: Request):
    """Analyze target and create comprehensive profile using Intelligent Decision Engine"""
    try:
        data = await request.json()
        if not data or 'target' not in data:
            return JSONResponse({"error": "Target is required"}), 400

        target = data['target']
        logger.info(f"🧠 Analyzing target: {target}")

        # Use the decision engine to analyze the target
        profile = decision_engine.analyze_target(target)

        logger.info(f"✅ Target analysis completed for {target}")
        logger.info(f"📊 Target type: {profile.target_type.value}, Risk level: {profile.risk_level}")

        return JSONResponse({
            "success": True,
            "target_profile": profile.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error analyzing target: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/select-tools", methods=["POST"])
async def select_optimal_tools(request: Request):
    """Select optimal tools based on target profile and objective"""
    try:
        data = await request.json()
        if not data or 'target' not in data:
            return JSONResponse({"error": "Target is required"}), 400

        target = data['target']
        objective = data.get('objective', 'comprehensive')  # comprehensive, quick, stealth

        logger.info(f"🎯 Selecting optimal tools for {target} with objective: {objective}")

        # Analyze target first
        profile = decision_engine.analyze_target(target)

        # Select optimal tools
        selected_tools = decision_engine.select_optimal_tools(profile, objective)

        logger.info(f"✅ Selected {len(selected_tools)} tools for {target}")

        return JSONResponse({
            "success": True,
            "target": target,
            "objective": objective,
            "target_profile": profile.to_dict(),
            "selected_tools": selected_tools,
            "tool_count": len(selected_tools),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error selecting tools: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/optimize-parameters", methods=["POST"])
async def optimize_tool_parameters(request: Request):
    """Optimize tool parameters based on target profile and context"""
    try:
        data = await request.json()
        if not data or 'target' not in data or 'tool' not in data:
            return JSONResponse({"error": "Target and tool are required"}), 400

        target = data['target']
        tool = data['tool']
        context = data.get('context', {})

        logger.info(f"⚙️  Optimizing parameters for {tool} against {target}")

        # Analyze target first
        profile = decision_engine.analyze_target(target)

        # Optimize parameters
        optimized_params = decision_engine.optimize_parameters(tool, profile, context)

        logger.info(f"✅ Parameters optimized for {tool}")

        return JSONResponse({
            "success": True,
            "target": target,
            "tool": tool,
            "context": context,
            "target_profile": profile.to_dict(),
            "optimized_parameters": optimized_params,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error optimizing parameters: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/error-handling/statistics", methods=["GET"])
async def get_error_statistics(request: Request):
    """Get error handling statistics"""
    try:
        stats = error_handler.get_error_statistics()
        return JSONResponse({
            "success": True,
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting error statistics: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/scan/trivy", methods=["POST"])
async def trivy(request: Request):
    """Execute Trivy for container/filesystem vulnerability scanning"""
    try:
        params = await request.json()
        scan_type = params.get("scan_type", "image")  # image, fs, repo
        target = params.get("target", "")
        output_format = params.get("output_format", "json")
        severity = params.get("severity", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Trivy called without target parameter")
            return JSONResponse({
                "error": "Target parameter is required"
            }), 400

        command = f"trivy {scan_type} {target}"

        if output_format:
            command += f" --format {output_format}"

        if severity:
            command += f" --severity {severity}"

        if output_file:
            command += f" --output {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Trivy {scan_type} scan: {target}")
        result = execute_command(command)
        if output_file:
            result["output_file"] = output_file
        logger.info(f"📊 Trivy scan completed for {target}")
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"💥 Error in trivy endpoint: {str(e)}")
        return JSONResponse({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/audit/kube-bench", methods=["POST"])
async def kube_bench(request: Request):
    """Execute kube-bench for CIS Kubernetes benchmark checks"""
    try:
        params = await request.json()
        config_dir = params.get("config_dir", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        command = "kube-bench"

        if config_dir:
            command += f" --config-dir {config_dir}"

        if output_format:
            command += f" --{output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting kube-bench CIS benchmark")
        result = execute_command(command)
        logger.info(f"📊 kube-bench benchmark completed")
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"💥 Error in kube-bench endpoint: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/monitoring/falco", methods=["POST"])
async def falco(request: Request):
    """Execute Falco for runtime security monitoring"""
    try:
        params = await request.json()
        config_file = params.get("config_file", "")
        rules_file = params.get("rules_file", "")
        output_format = params.get("output_format", "json")
        duration = params.get("duration", 60)  # seconds
        additional_args = params.get("additional_args", "")

        command = f"timeout {duration} falco"

        if config_file:
            command += f" --config {config_file}"

        if rules_file:
            command += f" --rules {rules_file}"

        if output_format == "json":
            command += " --json"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🛡️  Starting Falco runtime monitoring for {duration}s")
        result = execute_command(command)
        logger.info(f"📊 Falco monitoring completed")
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"💥 Error in falco endpoint: {str(e)}")
        return JSONResponse({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/scan/kubescape", methods=["POST"])
async def kubescape(request: Request):
    """Execute Kubescape for kubernetes cluster security scanning"""
    try:
        params = await request.json()
        type = params.get("scan_type", "")
        target = params.get("target", "")
        namespace = params.get("namespace", "")
        output_format = params.get("output_format", "")
        additional_args = params.get("additional_args", "")

        command = f"kubescape"

        if type:
            command += f" scan {type}"

        if target:
            command += f" {target}"
                
        if namespace:
            command += f" --namespace {namespace}"

        if output_format:
            command += f" --format {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting kubescape kubernetes scan")
        result = execute_command(command)
        logger.info(f"📊 Kubescape scan completed")
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"💥 Error in kubescape endpoint: {str(e)}")
        return JSONResponse({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/audit/popeye", methods=["POST"])
async def popeye(request: Request):
    """Execute Popeye for kubernetes manifest audit"""
    try:
        params = await request.json()
        namespace = params.get("namespace", "default")
        output_format = params.get("output_format","json")
        additional_args = params.get("additional_args", "")

        command = f"popeye"
        
        if namespace:
            command += f" --namespace {namespace}"

        if output_format:
            command += f" --out {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Popeye Audit")
        result = execute_command(command)
        logger.info(f"📊 Popeye audit completed")
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"💥 Error in popeye endpoint: {str(e)}")
        return JSONResponse({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/scan/rbac-tool", methods=["POST"])
async def rbac_tool(request: Request):
    """Execute RBAC-Tool for kubernetes RBAC security scanning"""
    try:
        params = await request.json()
        manifest = params.get("manifest_path", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        command = f"rbac-tool analysis"

        if manifest:
            command += f" --config {manifest}"

        if output_format:
            command += f" --output {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting RBAC-Tool for RBAC kubernetes scan")
        result = execute_command(command)
        logger.info(f"📊 RBAC-Tool scan completed")
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"💥 Error in rbac-tool endpoint: {str(e)}")
        return JSONResponse({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/scan/kubesec", methods=["POST"])
async def kubesec(request: Request):
    """Execute Kubesec for kubernetes security risk analysis"""
    try:
        params = await request.json()
        manifest = params.get("manifest_path", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        command = f"kubesec scan"

        if manifest:
            command += f" {manifest}"

        if output_format:
            command += f" --output {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Kubesec scan")
        result = execute_command(command)
        logger.info(f"📊 Kubesec scan completed")
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"💥 Error in kubesec endpoint: {str(e)}")
        return JSONResponse({
            "error": f"Server error: {str(e)}"
        }), 500


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the AI API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    args = parser.parse_args()

    if args.debug:
        DEBUG_MODE = True
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    # Enhanced startup messages with beautiful formatting
    startup_info = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Starting AI Tools API Server{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}🌐 Port:{ModernVisualEngine.COLORS['RESET']} {API_PORT}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}🔧 Debug Mode:{ModernVisualEngine.COLORS['RESET']} {DEBUG_MODE}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}💾 Cache Size:{ModernVisualEngine.COLORS['RESET']} {CACHE_SIZE} | TTL: {CACHE_TTL}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['TERMINAL_GRAY']}⏱️  Command Timeout:{ModernVisualEngine.COLORS['RESET']} {COMMAND_TIMEOUT}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}✨ Enhanced Visual Engine:{ModernVisualEngine.COLORS['RESET']} Active
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""

    for line in startup_info.strip().split('\n'):
        if line.strip():
            logger.info(line)

    uvicorn.run("mcpServer:app", host=API_HOST, port=API_PORT, reload=DEBUG_MODE)