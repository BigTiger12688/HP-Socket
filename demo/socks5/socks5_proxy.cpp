#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <csignal>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

struct ProxyConfig {
        std::string listen_host;
        std::string listen_port;
        std::string username;
        std::string password;
};

class Socket {
public:
        explicit Socket(int fd = -1) noexcept : fd_(fd) {}
        ~Socket() { Close(); }

        Socket(const Socket&) = delete;
        Socket& operator=(const Socket&) = delete;

        Socket(Socket&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
        Socket& operator=(Socket&& other) noexcept {
                if(this != &other) {
                        Close();
                        fd_ = other.fd_;
                        other.fd_ = -1;
                }
                return *this;
        }

        int get() const noexcept { return fd_; }
        int release() noexcept {
                int fd = fd_;
                fd_ = -1;
                return fd;
        }

        void reset(int fd = -1) noexcept {
                if(fd_ != fd) {
                        Close();
                        fd_ = fd;
                }
        }

private:
        void Close() noexcept {
                if(fd_ >= 0) {
                        ::close(fd_);
                        fd_ = -1;
                }
        }

        int fd_;
};

std::atomic<bool> g_running{true};

void SignalHandler(int) { g_running = false; }

bool SetSocketReuse(int fd) {
        int opt = 1;
        return ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0;
}

bool SendAll(int fd, const void* data, size_t len) {
        const uint8_t* ptr = static_cast<const uint8_t*>(data);
        size_t total = 0;
        while(total < len) {
                ssize_t sent = ::send(fd, ptr + total, len - total, 0);
                if(sent < 0) {
                        if(errno == EINTR)
                                continue;
                        return false;
                }
                total += static_cast<size_t>(sent);
        }
        return true;
}

bool RecvAll(int fd, void* data, size_t len) {
        uint8_t* ptr = static_cast<uint8_t*>(data);
        size_t total = 0;
        while(total < len) {
                ssize_t recvd = ::recv(fd, ptr + total, len - total, 0);
                if(recvd == 0)
                        return false;
                if(recvd < 0) {
                        if(errno == EINTR)
                                continue;
                        return false;
                }
                total += static_cast<size_t>(recvd);
        }
        return true;
}

Socket CreateListeningSocket(const ProxyConfig& config) {
        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        struct addrinfo* result = nullptr;
        int err = ::getaddrinfo(config.listen_host.empty() ? nullptr : config.listen_host.c_str(), config.listen_port.c_str(), &hints, &result);
        if(err != 0) {
                std::cerr << "getaddrinfo failed: " << gai_strerror(err) << std::endl;
                return Socket();
        }

        Socket listen_sock;
        for(struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
                Socket candidate(::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol));
                if(candidate.get() < 0)
                        continue;

                if(!SetSocketReuse(candidate.get()))
                        continue;

                if(::bind(candidate.get(), rp->ai_addr, rp->ai_addrlen) == 0) {
                        if(::listen(candidate.get(), SOMAXCONN) == 0) {
                                listen_sock = std::move(candidate);
                                break;
                        }
                }
        }

        ::freeaddrinfo(result);

        if(listen_sock.get() < 0)
                std::cerr << "Failed to create listening socket" << std::endl;
        return listen_sock;
}

bool SendMethodSelectionReply(int fd, bool success) {
        uint8_t response[2] = {0x05, static_cast<uint8_t>(success ? 0x02 : 0xFF)};
        return SendAll(fd, response, sizeof(response));
}

bool HandleAuthentication(int fd, const ProxyConfig& config) {
        uint8_t header[2];
        if(!RecvAll(fd, header, sizeof(header)))
                return false;
        if(header[0] != 0x05)
                return false;

        const uint8_t method_count = header[1];
        std::vector<uint8_t> methods(method_count);
        if(method_count > 0 && !RecvAll(fd, methods.data(), methods.size()))
                return false;

        bool supports_password = false;
        for(uint8_t m : methods) {
                if(m == 0x02) {
                        supports_password = true;
                        break;
                }
        }

        if(!SendMethodSelectionReply(fd, supports_password))
                return false;
        if(!supports_password)
                return false;

        uint8_t version = 0;
        if(!RecvAll(fd, &version, 1))
                return false;
        if(version != 0x01)
                return false;

        uint8_t ulen = 0;
        if(!RecvAll(fd, &ulen, 1))
                return false;

        std::vector<char> user(ulen);
        if(ulen > 0 && !RecvAll(fd, user.data(), user.size()))
                return false;

        uint8_t plen = 0;
        if(!RecvAll(fd, &plen, 1))
                return false;

        std::vector<char> pass(plen);
        if(plen > 0 && !RecvAll(fd, pass.data(), pass.size()))
                return false;

        bool ok = (std::string(user.begin(), user.end()) == config.username) &&
                  (std::string(pass.begin(), pass.end()) == config.password);

        uint8_t reply[2] = {0x01, static_cast<uint8_t>(ok ? 0x00 : 0x01)};
        SendAll(fd, reply, sizeof(reply));

        return ok;
}

bool ReadAddress(int fd, int& family, std::string& host, uint16_t& port) {
        uint8_t header[4];
        if(!RecvAll(fd, header, sizeof(header)))
                return false;
        if(header[0] != 0x05 || header[2] != 0x00)
                return false;
        if(header[1] != 0x01) // CONNECT
                return false;

        uint8_t atyp = header[3];
        if(atyp == 0x01) { // IPv4
                family = AF_INET;
                uint8_t addr[4];
                if(!RecvAll(fd, addr, sizeof(addr)))
                        return false;
                char buf[INET_ADDRSTRLEN];
                if(::inet_ntop(AF_INET, addr, buf, sizeof(buf)) == nullptr)
                        return false;
                host = buf;
        } else if(atyp == 0x04) { // IPv6
                family = AF_INET6;
                uint8_t addr[16];
                if(!RecvAll(fd, addr, sizeof(addr)))
                        return false;
                char buf[INET6_ADDRSTRLEN];
                if(::inet_ntop(AF_INET6, addr, buf, sizeof(buf)) == nullptr)
                        return false;
                host = buf;
        } else if(atyp == 0x03) { // Domain
                family = AF_UNSPEC;
                uint8_t len = 0;
                if(!RecvAll(fd, &len, 1))
                        return false;
                std::vector<char> domain(len);
                if(len > 0 && !RecvAll(fd, domain.data(), domain.size()))
                        return false;
                host.assign(domain.begin(), domain.end());
        } else {
                return false;
        }

        uint8_t port_bytes[2];
        if(!RecvAll(fd, port_bytes, sizeof(port_bytes)))
                return false;
        port = static_cast<uint16_t>(port_bytes[0] << 8 | port_bytes[1]);
        return true;
}

Socket ConnectRemote(const std::string& host, uint16_t port, int family_hint) {
        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = family_hint == AF_UNSPEC ? AF_UNSPEC : family_hint;
        hints.ai_socktype = SOCK_STREAM;

        std::ostringstream port_stream;
        port_stream << port;

        struct addrinfo* result = nullptr;
        int err = ::getaddrinfo(host.c_str(), port_stream.str().c_str(), &hints, &result);
        if(err != 0) {
                std::cerr << "Failed to resolve target " << host << ": " << gai_strerror(err) << std::endl;
                return Socket();
        }

        Socket remote;
        for(struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
                Socket candidate(::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol));
                if(candidate.get() < 0)
                        continue;

                if(::connect(candidate.get(), rp->ai_addr, rp->ai_addrlen) == 0) {
                        remote = std::move(candidate);
                        break;
                }
        }

        ::freeaddrinfo(result);

        return remote;
}

bool SendConnectionReply(int client_fd, int remote_fd) {
        struct sockaddr_storage local_addr;
        socklen_t addrlen = sizeof(local_addr);
        if(::getsockname(remote_fd, reinterpret_cast<struct sockaddr*>(&local_addr), &addrlen) != 0)
                return false;

        uint8_t response[4 + 16 + 2];
        size_t size = 0;
        response[size++] = 0x05;
        response[size++] = 0x00;
        response[size++] = 0x00;

        if(local_addr.ss_family == AF_INET) {
                response[size++] = 0x01;
                const auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(&local_addr);
                std::memcpy(response + size, &addr_in->sin_addr, 4);
                size += 4;
                std::memcpy(response + size, &addr_in->sin_port, 2);
                size += 2;
        } else if(local_addr.ss_family == AF_INET6) {
                response[size++] = 0x04;
                const auto* addr_in6 = reinterpret_cast<const struct sockaddr_in6*>(&local_addr);
                std::memcpy(response + size, &addr_in6->sin6_addr, 16);
                size += 16;
                std::memcpy(response + size, &addr_in6->sin6_port, 2);
                size += 2;
        } else {
                return false;
        }

        return SendAll(client_fd, response, size);
}

bool RelayTraffic(int client_fd, int remote_fd) {
        constexpr size_t kBufferSize = 32 * 1024;
        std::vector<uint8_t> buffer(kBufferSize);

        struct pollfd fds[2];
        fds[0].fd = client_fd;
        fds[0].events = POLLIN;
        fds[1].fd = remote_fd;
        fds[1].events = POLLIN;

        while(true) {
                int ready = ::poll(fds, 2, -1);
                if(ready < 0) {
                        if(errno == EINTR)
                                continue;
                        return false;
                }

                for(int i = 0; i < 2; ++i) {
                        if(fds[i].revents & POLLIN) {
                                int src = fds[i].fd;
                                int dst = fds[1 - i].fd;

                                ssize_t recvd = ::recv(src, buffer.data(), buffer.size(), 0);
                                if(recvd == 0)
                                        return true;
                                if(recvd < 0) {
                                        if(errno == EINTR)
                                                continue;
                                        return false;
                                }

                                if(!SendAll(dst, buffer.data(), static_cast<size_t>(recvd)))
                                        return false;
                        }
                        if(fds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
                                return false;
                }
        }
}

void HandleClient(int client_fd, ProxyConfig config) {
        Socket client(client_fd);

        struct sockaddr_storage peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        if(::getpeername(client.get(), reinterpret_cast<struct sockaddr*>(&peer_addr), &peer_len) == 0) {
                char host[NI_MAXHOST];
                char serv[NI_MAXSERV];
                if(::getnameinfo(reinterpret_cast<struct sockaddr*>(&peer_addr), peer_len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                        std::cout << "New connection from " << host << ":" << serv << std::endl;
                }
        }

        if(!HandleAuthentication(client.get(), config)) {
                std::cout << "Authentication failed" << std::endl;
                return;
        }

        int family = AF_UNSPEC;
        std::string target_host;
        uint16_t target_port = 0;
        if(!ReadAddress(client.get(), family, target_host, target_port)) {
                std::cout << "Failed to read Socks5 request" << std::endl;
                return;
        }

        Socket remote = ConnectRemote(target_host, target_port, family);
        if(remote.get() < 0) {
                std::cout << "Unable to reach target " << target_host << ":" << target_port << std::endl;
                return;
        }

        if(!SendConnectionReply(client.get(), remote.get())) {
                std::cout << "Failed to send connection reply" << std::endl;
                return;
        }

        std::cout << "Proxying " << target_host << ":" << target_port << std::endl;
        RelayTraffic(client.get(), remote.get());
}

void AcceptLoop(Socket listen_sock, ProxyConfig config) {
        while(g_running) {
                struct sockaddr_storage addr;
                socklen_t addrlen = sizeof(addr);
                int client_fd = ::accept(listen_sock.get(), reinterpret_cast<struct sockaddr*>(&addr), &addrlen);
                if(client_fd < 0) {
                        if(errno == EINTR)
                                continue;
                        if(errno == EBADF || errno == EINVAL)
                                break;
                        std::cerr << "accept failed: " << std::strerror(errno) << std::endl;
                        continue;
                }

                std::thread(HandleClient, client_fd, config).detach();
        }
}

} // namespace

int main(int argc, char* argv[]) {
        if(argc != 5) {
                std::cerr << "Usage: " << argv[0] << " <listen_host> <listen_port> <username> <password>" << std::endl;
                return 1;
        }

        ProxyConfig config;
        config.listen_host = argv[1];
        config.listen_port = argv[2];
        config.username = argv[3];
        config.password = argv[4];

        std::signal(SIGINT, SignalHandler);
        std::signal(SIGTERM, SignalHandler);

        Socket listen_sock = CreateListeningSocket(config);
        if(listen_sock.get() < 0)
                return 1;

        std::cout << "Listening on " << config.listen_host << ":" << config.listen_port << std::endl;
        AcceptLoop(std::move(listen_sock), config);

        std::cout << "Shutting down" << std::endl;
        return 0;
}
