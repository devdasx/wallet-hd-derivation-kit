# Offline-only runtime guarantee

The libraries and `wallethd` binary contain no HTTP client, RPC client, telemetry, analytics, balance lookup, DNS lookup, remote configuration, update check, or package download code. Derivation depends only on caller-supplied mnemonic/seed/key data and local computation.

Package managers naturally use the network while installing dependencies. `install.sh` and `install.ps1` download a tagged GitHub release and verify its checksum. Those distribution actions are separate from the installed library and CLI runtime.

CI verifies this claim after dependencies are installed by running examples and vectors in a network-disabled environment. Consumers needing a stronger boundary should vendor verified artifacts, pin checksums, deny network access at the OS/container level, and review their complete application dependency graph.
