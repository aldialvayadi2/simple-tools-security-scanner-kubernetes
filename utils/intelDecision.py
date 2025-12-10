# ============================================================================
# INTELLIGENT DECISION ENGINE (v6.0 ENHANCEMENT)
# ============================================================================

import urllib.parse
import re
import socket
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List, Set

class TargetType(Enum):
    """Enumeration of different target types for intelligent analysis"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"

class TechnologyStack(Enum):
    """Common technology stacks for targeted testing"""
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"

@dataclass
class TargetProfile:
    """Comprehensive target analysis profile for intelligent decision making"""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technologies: List[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert TargetProfile to dictionary for JSON serialization"""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": [tech.value for tech in self.technologies],
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "security_headers": self.security_headers,
            "ssl_info": self.ssl_info,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score
        }

@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    tool: str
    parameters: Dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int  # seconds
    dependencies: List[str] = field(default_factory=list)

class AttackChain:
    """Represents a sequence of attacks for maximum impact"""
    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability: float = 0.0
        self.estimated_time: int = 0
        self.required_tools: Set[str] = set()
        self.risk_level: str = "unknown"

    def add_step(self, step: AttackStep):
        """Add a step to the attack chain"""
        self.steps.append(step)
        self.required_tools.add(step.tool)
        self.estimated_time += step.execution_time_estimate

    def calculate_success_probability(self):
        """Calculate overall success probability of the attack chain"""
        if not self.steps:
            self.success_probability = 0.0
            return

        # Use compound probability for sequential steps
        prob = 1.0
        for step in self.steps:
            prob *= step.success_probability

        self.success_probability = prob

    def to_dict(self) -> Dict[str, Any]:
        """Convert AttackChain to dictionary"""
        return {
            "target": self.target_profile.target,
            "steps": [
                {
                    "tool": step.tool,
                    "parameters": step.parameters,
                    "expected_outcome": step.expected_outcome,
                    "success_probability": step.success_probability,
                    "execution_time_estimate": step.execution_time_estimate,
                    "dependencies": step.dependencies
                }
                for step in self.steps
            ],
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "required_tools": list(self.required_tools),
            "risk_level": self.risk_level
        }

class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization engine"""

    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()
        self.technology_signatures = self._initialize_technology_signatures()
        self.attack_patterns = self._initialize_attack_patterns()
        self._use_advanced_optimizer = True  # Enable advanced optimization by default

    def _initialize_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Initialize tool effectiveness ratings for different target types"""
        return {
            TargetType.CLOUD_SERVICE.value: {
                "trivy": 0.9,  # Excellent for container scanning
                "kube-bench": 0.88,  # Great for CIS benchmarks
                "falco": 0.87,  # Great for runtime monitoring
                "kubescape": 0.88,
                "rbac-tool": 0.87,
                "cdk": 0.89,
                "kubesec": 0.9,
                "popeye": 0.88
            }
        }

    def _initialize_technology_signatures(self) -> Dict[str, Dict[str, List[str]]]:
        """Initialize technology detection signatures"""
        return {
            "headers": {
                TechnologyStack.APACHE.value: ["Apache", "apache"],
                TechnologyStack.NGINX.value: ["nginx", "Nginx"],
                TechnologyStack.IIS.value: ["Microsoft-IIS", "IIS"],
                TechnologyStack.PHP.value: ["PHP", "X-Powered-By: PHP"],
                TechnologyStack.NODEJS.value: ["Express", "X-Powered-By: Express"],
                TechnologyStack.PYTHON.value: ["Django", "Flask", "Werkzeug"],
                TechnologyStack.JAVA.value: ["Tomcat", "JBoss", "WebLogic"],
                TechnologyStack.DOTNET.value: ["ASP.NET", "X-AspNet-Version"]
            },
            "content": {
                TechnologyStack.WORDPRESS.value: ["wp-content", "wp-includes", "WordPress"],
                TechnologyStack.DRUPAL.value: ["Drupal", "drupal", "/sites/default"],
                TechnologyStack.JOOMLA.value: ["Joomla", "joomla", "/administrator"],
                TechnologyStack.REACT.value: ["React", "react", "__REACT_DEVTOOLS"],
                TechnologyStack.ANGULAR.value: ["Angular", "angular", "ng-version"],
                TechnologyStack.VUE.value: ["Vue", "vue", "__VUE__"]
            },
            "ports": {
                TechnologyStack.APACHE.value: [80, 443, 8080, 8443],
                TechnologyStack.NGINX.value: [80, 443, 8080],
                TechnologyStack.IIS.value: [80, 443, 8080],
                TechnologyStack.NODEJS.value: [3000, 8000, 8080, 9000]
            }
        }

    def _initialize_attack_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize common attack patterns for different scenarios"""
        return {
              "kubernetes_security_assessment": [
                {"tool": "kube-bench", "priority": 1, "params": { "output_format": "json" }},
                
                {"tool": "kube-hunter", "priority": 2, "params": { "report": "json" }},
                
                {"tool": "falco", "priority": 3, "params": { "duration": 120, "output_format": "json" }},
                
                {"tool": "rbac-tool", "priority": 4, "params": { 
                    "mode": "analyze", 
                    "namespace": "all", 
                    "output_format": "json" 
                }},
                
                {"tool": "cdk", "priority": 5, "params": { 
                    "namespace": "default", 
                    "output_format": "json" 
                }},
                
                {"tool": "kubesec", "priority": 6, "params": { 
                    "file_path": "/data/manifests", 
                    "output_format": "json" 
                }},
                
                {"tool": "popeye", "priority": 7, "params": { 
                    "namespace": "all", 
                    "output_format": "json" 
                }}
            ],

            "container_security_assessment": [
                {"tool": "trivy", "priority": 1, "params": { 
                    "scan_type": "image", 
                    "severity": "HIGH,CRITICAL" 
                }},
                
                {"tool": "clair", "priority": 2, "params": { 
                    "output_format": "json" 
                }}
            ]
        }

    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create comprehensive profile"""
        profile = TargetProfile(target=target)

        # Determine target type
        profile.target_type = self._determine_target_type(target)

        # Basic network analysis
        if profile.target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            profile.ip_addresses = self._resolve_domain(target)

        # Technology detection (basic heuristics)
        if profile.target_type == TargetType.WEB_APPLICATION:
            profile.technologies = self._detect_technologies(target)
            profile.cms_type = self._detect_cms(target)

        # Calculate attack surface score
        profile.attack_surface_score = self._calculate_attack_surface(profile)

        # Determine risk level
        profile.risk_level = self._determine_risk_level(profile)

        # Set confidence score
        profile.confidence_score = self._calculate_confidence(profile)

        return profile

    def _determine_target_type(self, target: str) -> TargetType:
        """Determine the type of target for appropriate tool selection"""
        # URL patterns
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            if '/api/' in parsed.path or parsed.path.endswith('/api'):
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION

        # IP address pattern
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return TargetType.NETWORK_HOST

        # Domain name pattern
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return TargetType.WEB_APPLICATION

        return TargetType.UNKNOWN

    def _resolve_domain(self, target: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            if target.startswith(('http://', 'https://')):
                hostname = urllib.parse.urlparse(target).hostname
            else:
                hostname = target

            if hostname:
                ip = socket.gethostbyname(hostname)
                return [ip]
        except Exception:
            pass
        return []

    def _calculate_attack_surface(self, profile: TargetProfile) -> float:
        """Calculate attack surface score based on profile"""
        score = 0.0

        # Base score by target type
        type_scores = {
            TargetType.WEB_APPLICATION: 7.0,
            TargetType.API_ENDPOINT: 6.0,
            TargetType.NETWORK_HOST: 8.0,
            TargetType.CLOUD_SERVICE: 5.0,
            TargetType.BINARY_FILE: 4.0
        }

        score += type_scores.get(profile.target_type, 3.0)

        # Add points for technologies
        score += len(profile.technologies) * 0.5

        # Add points for open ports
        score += len(profile.open_ports) * 0.3

        # Add points for subdomains
        score += len(profile.subdomains) * 0.2

        # CMS adds attack surface
        if profile.cms_type:
            score += 1.5

        return min(score, 10.0)  # Cap at 10.0

    def _determine_risk_level(self, profile: TargetProfile) -> str:
        """Determine risk level based on attack surface"""
        if profile.attack_surface_score >= 8.0:
            return "critical"
        elif profile.attack_surface_score >= 6.0:
            return "high"
        elif profile.attack_surface_score >= 4.0:
            return "medium"
        elif profile.attack_surface_score >= 2.0:
            return "low"
        else:
            return "minimal"

    def _calculate_confidence(self, profile: TargetProfile) -> float:
        """Calculate confidence score in the analysis"""
        confidence = 0.5  # Base confidence

        # Increase confidence based on available data
        if profile.ip_addresses:
            confidence += 0.1
        if profile.technologies and profile.technologies[0] != TechnologyStack.UNKNOWN:
            confidence += 0.2
        if profile.cms_type:
            confidence += 0.1
        if profile.target_type != TargetType.UNKNOWN:
            confidence += 0.1

        return min(confidence, 1.0)

    def select_optimal_tools(self, profile: TargetProfile, objective: str = "comprehensive") -> List[str]:
        """Select optimal tools based on target profile and objective"""
        target_type = profile.target_type.value
        effectiveness_map = self.tool_effectiveness.get(target_type, {})

        # Get base tools for target type
        base_tools = list(effectiveness_map.keys())

        # Apply objective-based filtering
        if objective == "quick":
            # Select top 3 most effective tools
            sorted_tools = sorted(base_tools, key=lambda t: effectiveness_map.get(t, 0), reverse=True)
            selected_tools = sorted_tools[:3]
        elif objective == "comprehensive":
            # Select all tools with effectiveness > 0.7
            selected_tools = [tool for tool in base_tools if effectiveness_map.get(tool, 0) > 0.7]
        else:
            selected_tools = base_tools

        return selected_tools

    def optimize_parameters(self, tool: str, profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Enhanced parameter optimization with advanced intelligence"""
        if context is None:
            context = {}

        # Fallback to legacy optimization for compatibility
        optimized_params = {}

        # Tool-specific parameter optimization
        if tool == "kube-hunter":
            optimized_params = self._optimize_kube_hunter_params(profile, context)
        elif tool == "trivy":
            optimized_params = self._optimize_trivy_params(profile, context)

        return optimized_params

    def enable_advanced_optimization(self):
        """Enable advanced parameter optimization"""
        self._use_advanced_optimizer = True

    def disable_advanced_optimization(self):
        """Disable advanced parameter optimization (use legacy)"""
        self._use_advanced_optimizer = False

    def _optimize_gobuster_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Gobuster parameters"""
        params = {"url": profile.target, "mode": "dir"}

        # Select wordlist based on detected technologies
        if TechnologyStack.PHP in profile.technologies:
            params["additional_args"] = "-x php,html,txt,xml"
        elif TechnologyStack.DOTNET in profile.technologies:
            params["additional_args"] = "-x asp,aspx,html,txt"
        elif TechnologyStack.JAVA in profile.technologies:
            params["additional_args"] = "-x jsp,html,txt,xml"
        else:
            params["additional_args"] = "-x html,php,txt,js"

        # Adjust threads based on target type
        if context.get("aggressive", False):
            params["additional_args"] += " -t 50"
        else:
            params["additional_args"] += " -t 20"

        return params

    def _optimize_kube_hunter_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize kube-hunter parameters"""
        params = {"report": "json"}

        # Set target based on context
        if context.get("kubernetes_target"):
            params["target"] = context["kubernetes_target"]
        elif context.get("cidr"):
            params["cidr"] = context["cidr"]
        elif context.get("interface"):
            params["interface"] = context["interface"]

        # Enable active hunting if specified
        if context.get("active_hunting", False):
            params["active"] = True

        return params

    def _optimize_trivy_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Trivy parameters"""
        params = {"target": profile.target, "output_format": "json"}

        # Determine scan type based on target
        if profile.target.startswith(('docker.io/', 'gcr.io/', 'quay.io/')) or ':' in profile.target:
            params["scan_type"] = "image"
        elif os.path.isdir(profile.target):
            params["scan_type"] = "fs"
        else:
            params["scan_type"] = "image"  # Default

        # Set severity filter
        if context.get("severity"):
            params["severity"] = context["severity"]
        else:
            params["severity"] = "HIGH,CRITICAL"

        return params

    def create_attack_chain(self, profile: TargetProfile, objective: str = "comprehensive") -> AttackChain:
        """Create an intelligent attack chain based on target profile"""
        chain = AttackChain(profile)

        # Select attack pattern based on target type and objective
        if profile.target_type == TargetType.CLOUD_SERVICE:
            if objective == "aws":
                pattern = self.attack_patterns["aws_security_assessment"]
            elif objective == "kubernetes":
                pattern = self.attack_patterns["kubernetes_security_assessment"]
            elif objective == "containers":
                pattern = self.attack_patterns["container_security_assessment"]
            elif objective == "iac":
                pattern = self.attack_patterns["iac_security_assessment"]
            else:
                pattern = self.attack_patterns["multi_cloud_assessment"]

        # Create attack steps
        for step_config in pattern:
            tool = step_config["tool"]
            optimized_params = self.optimize_parameters(tool, profile)

            # Calculate success probability based on tool effectiveness
            effectiveness = self.tool_effectiveness.get(profile.target_type.value, {}).get(tool, 0.5)
            success_prob = effectiveness * profile.confidence_score

            time_estimates = {
                # Image scanners
                "trivy": 180,                    # Image scan (HIGH,CRITICAL)

                # Kubernetes scanners
                "kube-bench": 120,               # CIS benchmark (fast)
                "kube-hunter": 300,              # Network probing, slowest
                "kubesec": 20,                   # YAML static analysis (very fast)
                "popeye": 30,                    # Linter (fast)
                "rbac-tool": 45,                 # RBAC graph analysis
                "cdk": 120,                      # CDK attacks (varies by scenario)

                # Runtime security
                "falco": 120,                    # Real-time monitoring
            }

            exec_time = time_estimates.get(tool, 180)

            step = AttackStep(
                tool=tool,
                parameters=optimized_params,
                expected_outcome=f"Discover vulnerabilities using {tool}",
                success_probability=success_prob,
                execution_time_estimate=exec_time
            )

            chain.add_step(step)

        # Calculate overall chain metrics
        chain.calculate_success_probability()
        chain.risk_level = profile.risk_level

        return chain

