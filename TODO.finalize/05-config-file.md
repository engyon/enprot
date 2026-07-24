# Config file + `enprot init` (deferred)

Project-level `.enprot.toml` with default separators, policy, casdir.
Requires serde + toml deps and a Config struct that integrates with
clap's layered defaults. Deferred because the design needs review:
should CLI override config, or config override built-in defaults?
Where does the config live (cwd, XDG, home)?
