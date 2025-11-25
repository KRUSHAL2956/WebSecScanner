"""WebSec Scanner - Web Application Security Testing"""

__version__ = "1.0.0"

# Package imports for easy access
from .scanners import XSSScanner, SQLIScanner, CSRFScanner
from .core.utils import SecurityUtils

__all__ = [
    'XSSScanner',
    'SQLIScanner', 
    'CSRFScanner',
    'SecurityUtils',
    '__version__',
    '__author__'
]