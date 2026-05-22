"""
Backwards-compatible wrapper for api.app

DEPRECATED: This module is kept for backwards compatibility only.
All functionality has been consolidated into api.main.py

For new code, import from api.main instead:
    from api.main import app

For legacy code, this still works:
    from api.app import app
"""

import importlib
import sys
import warnings
from pathlib import Path

import api.main as main_module

# Show deprecation warning
warnings.warn(
    "Importing from api.app is deprecated. Please use api.main instead: from api.main import app",
    DeprecationWarning,
    stacklevel=2,
)

# Ensure main.py can be imported
sys.path.insert(0, str(Path(__file__).parent))

# Re-export the app from main for backwards compatibility
importlib.reload(main_module)
app = main_module.app

__all__ = ["app"]


# Support running as standalone script
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
