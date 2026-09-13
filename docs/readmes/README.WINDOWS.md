# Windows checkout compatibility

The stray file under `mcp/servers/` whose name begins `Oops!` and contains literal
backslashes and pipe characters has been removed. Windows cannot represent that
filename, causing Git checkout and partial-commit operations to fail with
`invalid path` even when the requested changes concern other files.

The removal fixes repository compatibility with Windows. Future repository paths
must avoid Windows-reserved filename characters, including `<>:"\|?*`.
