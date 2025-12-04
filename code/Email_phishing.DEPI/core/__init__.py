"""
__init__.py
Main package definition file.
Defines the submodules that can be imported when using "from package import *".
"""

__all__ = [
    # Email Parsing Modules (Parsers)
    "mail_parser",      # (e.g., mail_parser.py)
    "mail_pars",        # (e.g., mail_pars.py)

    # Inspection Modules (Inspectors)
    "link_inspector",   # (for link inspection)
    "hdr_inspector",    # (for header inspection like SPF/DKIM/DMARC)
    "attach_inspector", # (for attachment inspection)
    
    # Main Aggregation and Analysis Unit
    "engine",           # (The unit that coordinates analysis and calculates the score)
]

# Note: You can add import statements here to facilitate access to key functions
# For example:
# from .engine import analyze_mail
