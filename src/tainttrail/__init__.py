"""TaintTrail: an attack-path guard for AI agents, built on the Relate embedded graph database.

Every tool call an agent makes becomes a node in a Relate graph. Untrusted content,
sensitive data and outbound actions are linked by evidence edges, and a tool call is
blocked when it would complete a path from untrusted input to data leaving the machine.
"""

__version__ = "0.1.0"
