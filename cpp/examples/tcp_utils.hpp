#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <netdb.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace sv2cpp::example::tcp {

class TcpSocket {
public:
    TcpSocket() = default;

    explicit TcpSocket(int fd)
        : fd_(fd) {}

    TcpSocket(const TcpSocket &) = delete;
    TcpSocket &operator=(const TcpSocket &) = delete;

    TcpSocket(TcpSocket &&other) noexcept
        : fd_(other.fd_) {
        other.fd_ = -1;
    }

    TcpSocket &operator=(TcpSocket &&other) noexcept {
        if (this != &other) {
            close();
            fd_ = other.fd_;
            other.fd_ = -1;
        }

        return *this;
    }

    ~TcpSocket() noexcept {
        close();
    }

    int fd() const {
        return fd_;
    }

    bool valid() const {
        return fd_ >= 0;
    }

    void close() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_ = -1;
};

inline std::string socket_error_message(const std::string &prefix) {
    return prefix + ": " + std::strerror(errno);
}

inline std::string port_to_string(std::uint16_t port) {
    return std::to_string(static_cast<unsigned int>(port));
}

inline TcpSocket connect_tcp(const std::string &host, std::uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *result = nullptr;
    const auto port_string = port_to_string(port);

    const int getaddrinfo_result = ::getaddrinfo(
        host.c_str(),
        port_string.c_str(),
        &hints,
        &result
    );

    if (getaddrinfo_result != 0) {
        throw std::runtime_error(
            "Failed to resolve " + host + ":" + port_string + ": " +
            ::gai_strerror(getaddrinfo_result)
        );
    }

    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> addresses(
        result,
        ::freeaddrinfo
    );

    int last_errno = 0;

    for (addrinfo *address = addresses.get(); address != nullptr; address = address->ai_next) {
        TcpSocket socket(::socket(
            address->ai_family,
            address->ai_socktype,
            address->ai_protocol
        ));

        if (!socket.valid()) {
            last_errno = errno;
            continue;
        }

        if (::connect(socket.fd(), address->ai_addr, address->ai_addrlen) == 0) {
            return socket;
        }

        last_errno = errno;
    }

    errno = last_errno;
    throw std::runtime_error(socket_error_message("Failed to connect"));
}

inline void send_all(int fd, const std::vector<std::uint8_t> &data) {
    std::size_t total_sent = 0;

    while (total_sent < data.size()) {
        const auto remaining = data.size() - total_sent;
        const auto sent = ::send(
            fd,
            data.data() + total_sent,
            remaining,
            0
        );

        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }

            throw std::runtime_error(socket_error_message("Failed to send data"));
        }

        if (sent == 0) {
            throw std::runtime_error("Socket closed while sending data");
        }

        total_sent += static_cast<std::size_t>(sent);
    }
}

inline std::vector<std::uint8_t> recv_some(int fd, std::size_t max_size) {
    std::vector<std::uint8_t> buffer(max_size);

    while (true) {
        const auto received = ::recv(fd, buffer.data(), buffer.size(), 0);

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }

            throw std::runtime_error(socket_error_message("Failed to receive data"));
        }

        if (received == 0) {
            throw std::runtime_error("Peer closed the connection");
        }

        buffer.resize(static_cast<std::size_t>(received));
        return buffer;
    }
}

inline std::vector<std::uint8_t> recv_exact(int fd, std::size_t size) {
    std::vector<std::uint8_t> buffer(size);
    std::size_t total_received = 0;

    while (total_received < buffer.size()) {
        const auto remaining = buffer.size() - total_received;
        const auto received = ::recv(
            fd,
            buffer.data() + total_received,
            remaining,
            0
        );

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }

            throw std::runtime_error(socket_error_message("Failed to receive data"));
        }

        if (received == 0) {
            throw std::runtime_error("Peer closed the connection while reading");
        }

        total_received += static_cast<std::size_t>(received);
    }

    return buffer;
}

} // namespace sv2cpp::example::tcp