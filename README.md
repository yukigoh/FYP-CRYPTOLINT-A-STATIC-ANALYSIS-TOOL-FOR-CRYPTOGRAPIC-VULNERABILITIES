# FYP-CRYPTOLINT-A-STATIC-ANALYSIS-TOOL-FOR-CRYPTOGRAPIC-VULNERABILITIES
CryptoLint is a desktop static analysis tool that scans Python source code for cryptographic vulnerabilities, built with a dark-themed GUI and powered by OWASP and NIST detection rulesets.
Features

Automatic scanning — detects vulnerabilities instantly when a file is opened or rules are changed, no manual trigger needed
OWASP Top 10 & NIST SP 800-131A — 36 built-in detection rules covering weak hashing, hardcoded secrets, insecure cipher modes, insufficient key sizes, and more
Custom rule sets — import your own JSON rule files; rules are grouped by set name with per-rule enable/disable, rename, and delete controls
Severity filtering — filter findings by Critical / High / Medium / Low in one click
Click-to-jump — click any vulnerability card to scroll and highlight the exact line in the code viewer
AST & Data Flow panels — visualise the Python AST tree and track sensitive variable usage across the file
Password-protected PDF export — generates a professional white-theme report with a cover page, findings index table, priority remediation actions, and detailed vulnerability cards
Persistent session — remembers open files, active rulesets, and custom rule states across restarts

Tech Stack
Python · Tkinter · ReportLab · pypdf · ast · re
Requirements
pip install reportlab pypdf
Place OWASP.json and NIST.json in the same directory as cryptolint.py before running.
