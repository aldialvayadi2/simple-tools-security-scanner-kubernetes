from utils.cacheControl import Cache
from utils.intelDecision import IntelligentDecisionEngine
from utils.errorHandling import IntelligentErrorHandler, GracefulDegradation, RateLimitDetector, FailureRecoverySystem, PerformanceMonitor
from utils.cveIntelligence import CVEIntelligenceManager
from utils.fileManager import FileOperationsManager
from utils.processMonitoring import EnhancedProcessManager, TelemetryCollector
from utils.processTermination import PythonEnvironmentManager

# Global decision engine instance
decision_engine = IntelligentDecisionEngine()

# Global error handler and degradation manager instances
error_handler = IntelligentErrorHandler()
degradation_manager = GracefulDegradation()

# Global instances
rate_limiter = RateLimitDetector()
failure_recovery = FailureRecoverySystem()
performance_monitor = PerformanceMonitor()
enhanced_process_manager = EnhancedProcessManager()

# Global environment manager
env_manager = PythonEnvironmentManager()

# Global cache instance
cache = Cache()

# Global telemetry collector
telemetry = TelemetryCollector()

# Global intelligence managers
cve_intelligence = CVEIntelligenceManager()

# Global file operations manager
file_manager = FileOperationsManager()