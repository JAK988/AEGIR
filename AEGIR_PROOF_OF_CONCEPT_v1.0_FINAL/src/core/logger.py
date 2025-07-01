"""
Système de logging structuré pour Aegir
"""

import logging
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class LogEntry:
    """Structure d'une entrée de log."""
    timestamp: str
    level: str
    module: str
    function: str
    message: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration: Optional[float] = None


class StructuredFormatter(logging.Formatter):
    """Formateur de logs structuré."""
    
    def format(self, record):
        """Formate un record de log."""
        log_entry = LogEntry(
            timestamp=datetime.fromtimestamp(record.created).isoformat(),
            level=record.levelname,
            module=record.module,
            function=record.funcName,
            message=record.getMessage(),
            data=getattr(record, 'data', None),
            error=getattr(record, 'error', None),
            duration=getattr(record, 'duration', None)
        )
        
        return json.dumps(asdict(log_entry), ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Formateur pour la console avec couleurs."""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        """Formate un record pour la console."""
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        
        # Format de base
        formatted = f"{color}[{timestamp}] {record.levelname:8} | {record.module:15} | {record.getMessage()}{reset}"
        
        # Ajouter les données supplémentaires si présentes
        if hasattr(record, 'data') and record.data:
            formatted += f"\n{color}  └─ Data: {json.dumps(record.data, indent=2)}{reset}"
        
        if hasattr(record, 'error') and record.error:
            formatted += f"\n{color}  └─ Error: {record.error}{reset}"
        
        if hasattr(record, 'duration') and record.duration:
            formatted += f"\n{color}  └─ Duration: {record.duration:.3f}s{reset}"
        
        return formatted


class AegirLogger:
    """Logger principal d'Aegir."""
    
    def __init__(self, name: str = "aegir", level: str = "INFO", log_dir: str = "logs"):
        """Initialise le logger."""
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Créer le logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Éviter la duplication des handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Configure les handlers de logging."""
        # Handler pour la console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = ConsoleFormatter()
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Handler pour les logs structurés (JSON)
        json_handler = logging.FileHandler(self.log_dir / "aegir.json")
        json_handler.setLevel(logging.DEBUG)
        json_formatter = StructuredFormatter()
        json_handler.setFormatter(json_formatter)
        self.logger.addHandler(json_handler)
        
        # Handler pour les logs d'erreurs
        error_handler = logging.FileHandler(self.log_dir / "errors.log")
        error_handler.setLevel(logging.ERROR)
        error_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s'
        )
        error_handler.setFormatter(error_formatter)
        self.logger.addHandler(error_handler)
    
    def log_with_data(self, level: str, message: str, data: Optional[Dict[str, Any]] = None, 
                     error: Optional[str] = None, duration: Optional[float] = None):
        """Log avec des données supplémentaires."""
        extra = {}
        if data:
            extra['data'] = data
        if error:
            extra['error'] = error
        if duration:
            extra['duration'] = duration
        
        log_method = getattr(self.logger, level.lower())
        log_method(message, extra=extra)
    
    def debug(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log de debug."""
        self.log_with_data('DEBUG', message, data)
    
    def info(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log d'information."""
        self.log_with_data('INFO', message, data)
    
    def warning(self, message: str, data: Optional[Dict[str, Any]] = None, error: Optional[str] = None):
        """Log d'avertissement."""
        self.log_with_data('WARNING', message, data, error)
    
    def error(self, message: str, data: Optional[Dict[str, Any]] = None, error: Optional[str] = None):
        """Log d'erreur."""
        self.log_with_data('ERROR', message, data, error)
    
    def critical(self, message: str, data: Optional[Dict[str, Any]] = None, error: Optional[str] = None):
        """Log critique."""
        self.log_with_data('CRITICAL', message, data, error)
    
    def log_operation(self, operation: str, target: str, duration: float, 
                     success: bool, data: Optional[Dict[str, Any]] = None):
        """Log une opération avec durée et statut."""
        status = "SUCCESS" if success else "FAILED"
        message = f"{operation} on {target} - {status}"
        
        if data:
            data['operation'] = operation
            data['target'] = target
            data['success'] = success
        
        level = 'INFO' if success else 'ERROR'
        self.log_with_data(level, message, data, duration=duration)


# Logger global
logger = AegirLogger()


def get_logger(name: str = None) -> AegirLogger:
    """Obtient un logger."""
    if name:
        return AegirLogger(name)
    return logger


# Décorateur pour logger les fonctions
def log_function(func):
    """Décorateur pour logger automatiquement les appels de fonction."""
    def wrapper(*args, **kwargs):
        start_time = datetime.now()
        
        try:
            result = func(*args, **kwargs)
            duration = (datetime.now() - start_time).total_seconds()
            
            logger.log_operation(
                operation=func.__name__,
                target=str(args[0]) if args else "unknown",
                duration=duration,
                success=True,
                data={'args': str(args), 'kwargs': str(kwargs)}
            )
            
            return result
        
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            
            logger.log_operation(
                operation=func.__name__,
                target=str(args[0]) if args else "unknown",
                duration=duration,
                success=False,
                data={'args': str(args), 'kwargs': str(kwargs)},
                error=str(e)
            )
            
            raise
    
    return wrapper


# Décorateur pour logger les fonctions asynchrones
def log_async_function(func):
    """Décorateur pour logger automatiquement les appels de fonction asynchrone."""
    async def wrapper(*args, **kwargs):
        start_time = datetime.now()
        
        try:
            result = await func(*args, **kwargs)
            duration = (datetime.now() - start_time).total_seconds()
            
            logger.log_operation(
                operation=func.__name__,
                target=str(args[0]) if args else "unknown",
                duration=duration,
                success=True,
                data={'args': str(args), 'kwargs': str(kwargs)}
            )
            
            return result
        
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            
            logger.log_operation(
                operation=func.__name__,
                target=str(args[0]) if args else "unknown",
                duration=duration,
                success=False,
                data={'args': str(args), 'kwargs': str(kwargs)},
                error=str(e)
            )
            
            raise
    
    return wrapper 