"""``python -m tainttrail``.

The hook path is the one that runs for every tool call, in a process of its own, so it does
not import the command line, the reports or anything else it will not use.
"""

import sys


def main() -> int:
    if sys.argv[1:2] == ["hook"] and sys.argv[2:3] in ([], ["claude-code"]):
        from .hooks.claude_code import main as hook

        return hook()
    from .cli import main as cli

    return cli()


if __name__ == "__main__":
    raise SystemExit(main())
