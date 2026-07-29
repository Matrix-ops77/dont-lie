"""Convenience entry point when running from the workspace parent directory.

The installable package lives in ``dontlie/dontlie``. Normal users should
install the project and invoke the ``dontlie`` console script; this shim keeps
``python -m dontlie`` useful from the enclosing multi-project workspace.
"""

from .dontlie.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
