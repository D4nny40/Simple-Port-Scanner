#include "PortScanner.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

const std::unordered_map<std::uint16_t, std::string> PortScanner::known_ports_ = {
    {20, "FTP-DATA"},
    {21, "FTP"},
    {22, "SSH"},
    {23, "TELNET"},
    {25, "SMTP"},
    {53, "DNS"},
    {67, "DHCP"},
    {68, "DHCP"},
    {80, "HTTP"},
    {110, "POP3"},
    {123, "NTP"},
    {135, "MS-RPC"},
    {139, "NETBIOS"},
    {143, "IMAP"},
    {161, "SNMP"},
    {389, "LDAP"},
    {443, "HTTPS"},
    {445, "SMB"},
    {465, "SMTPS"},
    {587, "SMTP-SUBMISSION"},
    {993, "IMAPS"},
    {995, "POP3S"},
    {1433, "MSSQL"},
    {1521, "ORACLE"},
    {3306, "MYSQL"},
    {3389, "RDP"},
    {5432, "POSTGRESQL"},
    {5900, "VNC"},
    {6379, "REDIS"},
    {8080, "HTTP-ALT"}
};

PortScanner::PortScanner() {
    WSADATA wsa_data{};

    int startup_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    if (startup_result != 0) {
        throw std::runtime_error("WSAStartup failed. WinSock could not be started.");
    }
}

PortScanner::~PortScanner() {
    WSACleanup();
}

void PortScanner::set_options(
    const std::string& target,
    const std::string& port_expression,
    int max_threads,
    int timeout_seconds
) {
    if (target.empty()) {
        throw std::runtime_error("Target cannot be empty.");
    }

    if (max_threads < 1) {
        throw std::runtime_error("Threads must be at least 1.");
    }

    if (timeout_seconds < 1) {
        throw std::runtime_error("Timeout must be at least 1 second.");
    }

    target_ = target;
    max_threads_ = max_threads;
    timeout_seconds_ = timeout_seconds;

    parse_ports(port_expression);
    resolve_target();
}

void PortScanner::parse_ports(const std::string& port_expression) {
    if (port_expression.empty()) {
        throw std::runtime_error("Port expression cannot be empty.");
    }

    std::string cleaned;

    for (char c : port_expression) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            cleaned += c;
        }
    }

    std::stringstream stream(cleaned);
    std::string token;
    std::set<int> unique_ports;

    while (std::getline(stream, token, ',')) {
        if (token.empty()) {
            continue;
        }

        std::size_t dash_position = token.find('-');

        if (dash_position == std::string::npos) {
            int port = std::stoi(token);

            if (port < 1 || port > 65535) {
                throw std::runtime_error("Port number out of range: " + token);
            }

            unique_ports.insert(port);
        } else {
            std::string start_text = token.substr(0, dash_position);
            std::string end_text = token.substr(dash_position + 1);

            if (start_text.empty() || end_text.empty()) {
                throw std::runtime_error("Invalid port range: " + token);
            }

            int start_port = std::stoi(start_text);
            int end_port = std::stoi(end_text);

            if (start_port < 1 || end_port > 65535 || start_port > end_port) {
                throw std::runtime_error("Invalid port range: " + token);
            }

            for (int port = start_port; port <= end_port; ++port) {
                unique_ports.insert(port);
            }
        }
    }

    if (unique_ports.empty()) {
        throw std::runtime_error("No valid ports were provided.");
    }

    while (!ports_.empty()) {
        ports_.pop();
    }

    for (int port : unique_ports) {
        ports_.push(static_cast<std::uint16_t>(port));
    }

    total_ports_ = static_cast<int>(ports_.size());
}

void PortScanner::resolve_target() {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;

    int resolve_result = getaddrinfo(
        target_.c_str(),
        nullptr,
        &hints,
        &result
    );

    if (resolve_result != 0 || result == nullptr) {
        throw std::runtime_error("Could not resolve target: " + target_);
    }

    addrinfo* selected = nullptr;

    for (addrinfo* current = result; current != nullptr; current = current->ai_next) {
        if (current->ai_family == AF_INET || current->ai_family == AF_INET6) {
            selected = current;
            break;
        }
    }

    if (selected == nullptr) {
        freeaddrinfo(result);
        throw std::runtime_error("No IPv4 or IPv6 address found for target.");
    }

    std::memcpy(
        &target_address_,
        selected->ai_addr,
        selected->ai_addrlen
    );

    target_address_length_ = static_cast<int>(selected->ai_addrlen);
    target_family_ = selected->ai_family;

    char host_buffer[NI_MAXHOST]{};

    int name_result = getnameinfo(
        reinterpret_cast<sockaddr*>(&target_address_),
        target_address_length_,
        host_buffer,
        NI_MAXHOST,
        nullptr,
        0,
        NI_NUMERICHOST
    );

    if (name_result == 0) {
        resolved_ip_ = host_buffer;
    } else {
        resolved_ip_ = target_;
    }

    freeaddrinfo(result);
}

void PortScanner::start() {
    std::cout << "\n";
    std::cout << "Simple Port Scanner - Version 1\n";
    std::cout << "================================\n";
    std::cout << "Target:      " << target_ << " (" << resolved_ip_ << ")\n";
    std::cout << "Ports:       " << total_ports_ << "\n";
    std::cout << "Threads:     " << max_threads_ << "\n";
    std::cout << "Timeout:     " << timeout_seconds_ << " seconds\n\n";
}

void PortScanner::run() {
    int worker_count = std::min(max_threads_, total_ports_);

    std::vector<std::thread> workers;
    workers.reserve(worker_count);

    for (int i = 0; i < worker_count; ++i) {
        workers.emplace_back([this]() {
            worker_loop();
        });
    }

    for (std::thread& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    std::sort(results_.begin(), results_.end(), [](const ScanResult& a, const ScanResult& b) {
        return a.port < b.port;
    });

    std::cout << std::left
              << std::setw(8) << "PORT"
              << std::setw(12) << "STATE"
              << std::setw(18) << "SERVICE"
              << "BANNER"
              << "\n";

    std::cout << std::string(70, '-') << "\n";

    for (const ScanResult& result : results_) {
        print_result(result);
    }

    print_summary();
}

bool PortScanner::pop_next_port(std::uint16_t& port) {
    std::lock_guard<std::mutex> lock(queue_mutex_);

    if (ports_.empty()) {
        return false;
    }

    port = ports_.front();
    ports_.pop();

    return true;
}

void PortScanner::worker_loop() {
    std::uint16_t port = 0;

    while (pop_next_port(port)) {
        ScanResult result = scan_port(port);
        store_result(result);
    }
}

PortScanner::ScanResult PortScanner::scan_port(std::uint16_t port) {
    SOCKET socket_handle = socket(target_family_, SOCK_STREAM, IPPROTO_TCP);

    if (socket_handle == INVALID_SOCKET) {
        return {port, PortState::Filtered, service_name(port), "---"};
    }

    sockaddr_storage endpoint = target_address_;

    if (endpoint.ss_family == AF_INET) {
        auto* ipv4 = reinterpret_cast<sockaddr_in*>(&endpoint);
        ipv4->sin_port = htons(port);
    } else if (endpoint.ss_family == AF_INET6) {
        auto* ipv6 = reinterpret_cast<sockaddr_in6*>(&endpoint);
        ipv6->sin6_port = htons(port);
    } else {
        closesocket(socket_handle);
        return {port, PortState::Filtered, service_name(port), "---"};
    }

    u_long non_blocking = 1;
    ioctlsocket(socket_handle, FIONBIO, &non_blocking);

    int connect_result = connect(
        socket_handle,
        reinterpret_cast<sockaddr*>(&endpoint),
        target_address_length_
    );

    if (connect_result == 0) {
        std::string banner = grab_banner(socket_handle);
        closesocket(socket_handle);
        return {port, PortState::Open, service_name(port), banner};
    }

    int connect_error = WSAGetLastError();

    if (
        connect_error != WSAEWOULDBLOCK &&
        connect_error != WSAEINPROGRESS &&
        connect_error != WSAEINVAL
    ) {
        closesocket(socket_handle);

        if (connect_error == WSAECONNREFUSED) {
            return {port, PortState::Closed, service_name(port), "---"};
        }

        return {port, PortState::Filtered, service_name(port), "---"};
    }

    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(socket_handle, &write_set);

    timeval timeout{};
    timeout.tv_sec = timeout_seconds_;
    timeout.tv_usec = 0;

    int select_result = select(
        0,
        nullptr,
        &write_set,
        nullptr,
        &timeout
    );

    if (select_result == 0) {
        closesocket(socket_handle);
        return {port, PortState::Filtered, service_name(port), "---"};
    }

    if (select_result == SOCKET_ERROR) {
        closesocket(socket_handle);
        return {port, PortState::Filtered, service_name(port), "---"};
    }

    int socket_error = 0;
    int socket_error_length = sizeof(socket_error);

    getsockopt(
        socket_handle,
        SOL_SOCKET,
        SO_ERROR,
        reinterpret_cast<char*>(&socket_error),
        &socket_error_length
    );

    if (socket_error == 0) {
        std::string banner = grab_banner(socket_handle);
        closesocket(socket_handle);
        return {port, PortState::Open, service_name(port), banner};
    }

    closesocket(socket_handle);

    if (socket_error == WSAECONNREFUSED) {
        return {port, PortState::Closed, service_name(port), "---"};
    }

    return {port, PortState::Filtered, service_name(port), "---"};
}

std::string PortScanner::grab_banner(SOCKET socket_handle) {
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(socket_handle, &read_set);

    timeval timeout{};
    timeout.tv_sec = banner_timeout_seconds_;
    timeout.tv_usec = 0;

    int select_result = select(
        0,
        &read_set,
        nullptr,
        nullptr,
        &timeout
    );

    if (select_result <= 0) {
        return "---";
    }

    std::array<char, 256> buffer{};

    int bytes_received = recv(
        socket_handle,
        buffer.data(),
        static_cast<int>(buffer.size()) - 1,
        0
    );

    if (bytes_received <= 0) {
        return "---";
    }

    std::string raw_banner(buffer.data(), bytes_received);
    return clean_banner(raw_banner);
}

void PortScanner::store_result(const ScanResult& result) {
    std::lock_guard<std::mutex> lock(results_mutex_);

    results_.push_back(result);

    switch (result.state) {
        case PortState::Open:
            ++open_ports_;
            break;
        case PortState::Closed:
            ++closed_ports_;
            break;
        case PortState::Filtered:
            ++filtered_ports_;
            break;
    }
}

void PortScanner::print_result(const ScanResult& result) const {
    std::cout << std::left
              << std::setw(8) << result.port
              << std::setw(12) << state_to_string(result.state)
              << std::setw(18) << result.service
              << result.banner
              << "\n";
}

void PortScanner::print_summary() const {
    std::cout << "\n";
    std::cout << "Scan Summary\n";
    std::cout << "============\n";
    std::cout << "Total ports scanned: " << total_ports_ << "\n";
    std::cout << "Open ports:          " << open_ports_ << "\n";
    std::cout << "Closed ports:        " << closed_ports_ << "\n";
    std::cout << "Filtered ports:      " << filtered_ports_ << "\n";
}

std::string PortScanner::service_name(std::uint16_t port) const {
    auto it = known_ports_.find(port);

    if (it != known_ports_.end()) {
        return it->second;
    }

    return "---";
}

std::string PortScanner::state_to_string(PortState state) const {
    switch (state) {
        case PortState::Open:
            return "OPEN";
        case PortState::Closed:
            return "CLOSED";
        case PortState::Filtered:
            return "FILTERED";
        default:
            return "UNKNOWN";
    }
}

std::string PortScanner::clean_banner(const std::string& raw_banner) const {
    std::string cleaned;

    for (char c : raw_banner) {
        unsigned char value = static_cast<unsigned char>(c);

        if (c == '\r' || c == '\n' || c == '\t') {
            cleaned += ' ';
        } else if (std::isprint(value)) {
            cleaned += c;
        }
    }

    while (cleaned.find("  ") != std::string::npos) {
        cleaned.erase(cleaned.find("  "), 1);
    }

    if (cleaned.empty()) {
        return "---";
    }

    return cleaned;
}
