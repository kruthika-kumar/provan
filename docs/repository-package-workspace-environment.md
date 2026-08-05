# Repository, package, workspace, and environment

The Community repository is the source and history boundary. The `provan-assurance` wheel contains only the `provan` runtime. A target repository is read-only input and is never a Provan workspace. `.provan` is local operator state; `PROVAN_HOME` may relocate it for isolation. `PROVAN_` variables configure Provan only and do not authorize target mutation.
