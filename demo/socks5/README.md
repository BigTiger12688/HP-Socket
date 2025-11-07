# TCP Socks5 Proxy Demo

This demo provides a minimal TCP Socks5 proxy server that enforces username/password authentication. It is implemented with portable POSIX sockets and does not depend on additional libraries beyond the C++17 standard library.

## Build

```bash
g++ -std=c++17 -Wall -Wextra -pedantic -pthread socks5_proxy.cpp -o socks5_proxy
```

## Usage

```bash
./socks5_proxy <listen_host> <listen_port> <username> <password>
```

* `listen_host` – Hostname or IP address to bind, for example `0.0.0.0`.
* `listen_port` – TCP port to bind (e.g. `1080`).
* `username` / `password` – Credentials required by connecting clients during the Socks5 authentication phase.

After starting the proxy you can configure your client application (browser, curl, etc.) to use a Socks5 proxy pointing at the configured host and port with the same credentials. The proxy currently supports the Socks5 `CONNECT` command and relays TCP traffic bidirectionally once the tunnel is established.
