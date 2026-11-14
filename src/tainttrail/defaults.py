"""Built-in defaults. Every list here can be extended from ``.tainttrail/config.toml``."""

from __future__ import annotations

# Hosts that are ordinary destinations in a development workflow. A trusted host only
# silences *context-level* findings (TT002, TT003). Evidence that sensitive data is
# actually carried to it (TT001, TT006) is never silenced by this list.
TRUSTED_HOSTS: tuple[str, ...] = (
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "gitlab.com",
    "bitbucket.org",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "proxy.golang.org",
    "sum.golang.org",
    "rubygems.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "deb.debian.org",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "dl-cdn.alpinelinux.org",
    "formulae.brew.sh",
    "docs.python.org",
    "developer.mozilla.org",
    "nodejs.org",
)

# Loopback and private ranges are not "external": data sent there does not leave the
# machine or the local network on its own.
LOCAL_HOSTS: tuple[str, ...] = ("localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal")

# Files whose content is treated as sensitive regardless of what is inside.
# Globs use ``fnmatch`` semantics on the absolute, ``~``-expanded POSIX path;
# ``**`` matches any number of directories.
SENSITIVE_PATHS: tuple[str, ...] = (
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/*.keystore",
    "**/id_rsa",
    "**/id_dsa",
    "**/id_ecdsa",
    "**/id_ed25519",
    "~/.ssh/**",
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.config/gcloud/**",
    "~/.azure/**",
    "~/.kube/config",
    "~/.docker/config.json",
    "~/.npmrc",
    "**/.npmrc",
    "~/.pypirc",
    "~/.netrc",
    "**/.netrc",
    "~/.git-credentials",
    "~/.config/gh/hosts.yml",
    "~/.gnupg/**",
    "~/.claude.json",
    "~/.claude/.credentials.json",
    "**/secrets.json",
    "**/secrets.yaml",
    "**/secrets.yml",
    "**/secrets.toml",
    "**/credentials.json",
    "**/service-account*.json",
    "**/terraform.tfstate",
    "**/terraform.tfstate.backup",
    "**/*.tfvars",
    "**/.htpasswd",
    "~/.bash_history",
    "~/.zsh_history",
    "/etc/shadow",
    "/proc/*/environ",
)

# Exceptions to SENSITIVE_PATHS: public halves of key pairs and templates.
SENSITIVE_PATH_EXCEPTIONS: tuple[str, ...] = (
    "**/.env.example",
    "**/.env.sample",
    "**/.env.template",
    "**/.env.dist",
    "**/*.pub",
    "~/.ssh/known_hosts",
    "~/.ssh/known_hosts.old",
)

# Files that change what an agent or the machine does later: instruction files,
# agent settings, autorun hooks, CI definitions. Writing these while the session holds
# untrusted content is how an injection persists.
PROTECTED_PATHS: tuple[str, ...] = (
    "**/CLAUDE.md",
    "**/CLAUDE.local.md",
    "**/AGENTS.md",
    "**/GEMINI.md",
    "**/.claude/**",
    "~/.claude/**",
    "**/.cursor/rules/**",
    "**/.cursorrules",
    "**/.windsurfrules",
    "**/.clinerules",
    "**/.github/copilot-instructions.md",
    "**/.github/workflows/**",
    "**/.gitlab-ci.yml",
    "**/.mcp.json",
    "**/.cursor/mcp.json",
    "**/.vscode/mcp.json",
    "**/.vscode/tasks.json",
    "**/.vscode/settings.json",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.config/fish/**",
    "**/.git/hooks/**",
    "**/.git/config",
    "**/.husky/**",
    "~/.gitconfig",
    "~/.ssh/authorized_keys",
    "~/.ssh/config",
    "**/.envrc",
    "**/.tainttrail/**",
)

# Files whose content can be written by third parties even though they are on disk.
UNTRUSTED_PATHS: tuple[str, ...] = (
    "**/node_modules/**",
    "**/site-packages/**",
    "**/dist-packages/**",
    "**/vendor/**",
    "**/third_party/**",
    "~/Downloads/**",
)

MODES: tuple[str, ...] = ("monitor", "guard", "strict")

MAX_CONTENT_BYTES = 262_144
MAX_CHUNKS_PER_CONTENT = 400
MAX_ENTITIES_PER_CONTENT = 200
LOCK_TIMEOUT_MS = 4_000
