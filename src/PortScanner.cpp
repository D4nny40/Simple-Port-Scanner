#include "PortScanner.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <cctype>
#include <cstring>

const std::unordered_map<int, std::string> PortScanner::common_services{
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
    {135, "MSRPC"},
    {139, "NETBIOS"},
    {143, "IMAP"},
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

PortScanner::PortScanner() = default;

PortScanner::~PortScanner()
{
    stop_winsock();
}

void PortScanner::set_options(
    const std::string& target,
    const std::string& port_expression,
    int max_threads,
    int timeout_seconds,
    const std::string& output_file
)
{
    target_ = target;
    port_expression_ = port_expression;
    max_threads_ = std::max(1, max_threads);
    timeout_seconds_ = std::max(1, timeout_seconds);
    output_file_ = output_file;
}

void PortScanner::start()
{
    start_winsock();
    resolve_target();

    std::vector<int> ports = parse_ports(port_expression_);

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        while (!port_queue_.empty()) {
            port_queue_.pop();
        }

        for (int port : ports) {
            port_queue_.push(port);
        }
    }

    results_.clear();

    total_ports_ = static_cast<int>(ports.size());
    open_ports_ = 0;
    closed_ports_ = 0;
    filtered_ports_ = 0;

    std::cout << "Simple Port Scanner - Version 2\n";
    std::cout << "================================\n";
    std::cout << "Target:      " << target_ << " (" << resolved_ip_ << ")\n";
    std::cout << "Ports:       " << total_ports_ << "\n";
    std::cout << "Threads:     " << max_threads_ << "\n";
    std::cout << "Timeout:     " << timeout_seconds_ << " seconds\n";

    if (!output_file_.empty()) {
        std::cout << "CSV output:  " << output_file_ << "\n";
    }

    std::cout << "\n";
}

void PortScanner::run()
{
    auto start_time = std::chrono::steady_clock::now();

    int worker_count = std::min(max_threads_, std::max(1, total_ports_));
    std::vector<std::thread> workers;
    workers.reserve(worker_count);

    for (int i = 0; i < worker_count; ++i) {
        workers.emplace_back(&PortScanner::worker_loop, this);
    }

    for (std::thread& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> duration = end_time - start_time;

    std::sort(results_.begin(), results_.end(),
        [](const ScanResult& left, const ScanResult& right) {
            return left.port < right.port;
        });

    if (output_file_.empty()) {
        print_results();
    }
    else {
        write_csv();
    }

    print_summary(duration.count());
}

void PortScanner::start_winsock()
{
    if (winsock_started_) {
        return;
    }

    WSADATA data{};
    int result = WSAStartup(MAKEWORD(2, 2), &data);

    if (result != 0) {
        throw std::runtime_error("WSAStartup failed");
    }

    winsock_started_ = true;
}

void PortScanner::stop_winsock()
{
    if (winsock_started_) {
        WSACleanup();
        winsock_started_ = false;
    }
}

void PortScanner::resolve_target()
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    int status = getaddrinfo(target_.c_str(), "0", &hints, &result);

    if (status != 0 || result == nullptr) {
        throw std::runtime_error("Could not resolve target: " + target_);
    }

    std::memcpy(&target_address_, result->ai_addr, result->ai_addrlen);
    target_address_length_ = static_cast<int>(result->ai_addrlen);

    char ip_buffer[INET6_ADDRSTRLEN]{};

    if (result->ai_family == AF_INET) {
        sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(result->ai_addr);
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_buffer, sizeof(ip_buffer));
    }
    else if (result->ai_family == AF_INET6) {
        sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(result->ai_addr);
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_buffer, sizeof(ip_buffer));
    }

    resolved_ip_ = ip_buffer[0] != '\0' ? ip_buffer : target_;

    freeaddrinfo(result);
}

std::vector<int> PortScanner::parse_ports(const std::string& expression) const
{
    std::vector<int> ports;
    std::stringstream expression_stream(expression);
    std::string token;

    while (std::getline(expression_stream, token, ',')) {
        token.erase(std::remove_if(token.begin(), token.end(),
            [](unsigned char c) { return std::isspace(c); }), token.end());

        if (token.empty()) {
            continue;
        }

        std::size_t dash_position = token.find('-');

        if (dash_position == std::string::npos) {
            int port = std::stoi(token);

            if (port < 1 || port > 65535) {
                throw std::runtime_error("Port out of range: " + token);
            }

            ports.push_back(port);
        }
        else {
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
                ports.push_back(port);
            }
        }
    }

    if (ports.empty()) {
        throw std::runtime_error("No valid ports were provided");
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());

    return ports;
}

void PortScanner::worker_loop()
{
    while (true) {
        int port = 0;

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);

            if (port_queue_.empty()) {
                return;
            }

            port = port_queue_.front();
            port_queue_.pop();
        }

        ScanResult result = scan_port(port);

        {
            std::lock_guard<std::mutex> lock(result_mutex_);

            results_.push_back(result);

            if (result.state == PortState::Open) {
                ++open_ports_;
            }
            else if (result.state == PortState::Closed) {
                ++closed_ports_;
            }
            else {
                ++filtered_ports_;
            }
        }
    }
}

ScanResult PortScanner::scan_port(int port) const
{
    ScanResult result;
    result.port = port;
    result.service = service_name(port);
    result.banner = "---";

    sockaddr_storage address = target_address_;

    if (address.ss_family == AF_INET) {
        sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(&address);
        ipv4->sin_port = htons(static_cast<u_short>(port));
    }
    else if (address.ss_family == AF_INET6) {
        sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(&address);
        ipv6->sin6_port = htons(static_cast<u_short>(port));
    }
    else {
        result.state = PortState::Filtered;
        return result;
    }

    SOCKET socket_handle = socket(address.ss_family, SOCK_STREAM, IPPROTO_TCP);

    if (socket_handle == INVALID_SOCKET) {
        result.state = PortState::Filtered;
        return result;
    }

    u_long non_blocking = 1;
    ioctlsocket(socket_handle, FIONBIO, &non_blocking);

    int connect_result = connect(
        socket_handle,
        reinterpret_cast<sockaddr*>(&address),
        target_address_length_
    );

    if (connect_result == SOCKET_ERROR) {
        int error = WSAGetLastError();

        if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS && error != WSAEINVAL) {
            result.state = PortState::Closed;
            closesocket(socket_handle);
            return result;
        }
    }

    fd_set write_set;
    fd_set error_set;

    FD_ZERO(&write_set);
    FD_ZERO(&error_set);

    FD_SET(socket_handle, &write_set);
    FD_SET(socket_handle, &error_set);

    timeval timeout{};
    timeout.tv_sec = timeout_seconds_;
    timeout.tv_usec = 0;

    int select_result = select(0, nullptr, &write_set, &error_set, &timeout);

    if (select_result > 0) {
        int socket_error = 0;
        int socket_error_size = sizeof(socket_error);

        getsockopt(
            socket_handle,
            SOL_SOCKET,
            SO_ERROR,
            reinterpret_cast<char*>(&socket_error),
            &socket_error_size
        );

        if (socket_error == 0) {
            result.state = PortState::Open;
            result.banner = grab_banner(socket_handle);
        }
        else {
            result.state = PortState::Closed;
        }
    }
    else if (select_result == 0) {
        result.state = PortState::Filtered;
    }
    else {
        result.state = PortState::Filtered;
    }

    closesocket(socket_handle);
    return result;
}

std::string PortScanner::grab_banner(SOCKET socket_handle) const
{
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(socket_handle, &read_set);

    timeval timeout{};
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int select_result = select(0, &read_set, nullptr, nullptr, &timeout);

    if (select_result <= 0) {
        return "---";
    }

    char buffer[256]{};
    int bytes_received = recv(socket_handle, buffer, sizeof(buffer) - 1, 0);

    if (bytes_received <= 0) {
        return "---";
    }

    return clean_banner(std::string(buffer, bytes_received));
}

std::string PortScanner::clean_banner(const std::string& banner) const
{
    std::string cleaned;

    for (char character : banner) {
        if (character == '\r' || character == '\n' || character == '\t') {
            cleaned += ' ';
        }
        else if (std::isprint(static_cast<unsigned char>(character))) {
            cleaned += character;
        }
    }

    while (!cleaned.empty() && cleaned.back() == ' ') {
        cleaned.pop_back();
    }

    if (cleaned.empty()) {
        return "---";
    }

    return cleaned;
}

std::string PortScanner::service_name(int port) const
{
    auto iterator = common_services.find(port);

    if (iterator == common_services.end()) {
        return "---";
    }

    return iterator->second;
}

std::string PortScanner::state_to_string(PortState state) const
{
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

void PortScanner::print_results() const
{
    std::cout << "PORT    STATE       SERVICE           BANNER\n";
    std::cout << "----------------------------------------------------------------------\n";

    for (const ScanResult& result : results_) {
        print_result(result);
    }

    std::cout << "\n";
}

void PortScanner::print_result(const ScanResult& result) const
{
    std::cout << std::left
              << std::setw(8) << result.port
              << std::setw(12) << state_to_string(result.state)
              << std::setw(18) << result.service
              << result.banner
              << "\n";
}

void PortScanner::print_summary(double duration_seconds) const
{
    std::cout << "Scan Summary\n";
    std::cout << "============\n";
    std::cout << "Total ports scanned: " << total_ports_ << "\n";
    std::cout << "Open ports:          " << open_ports_ << "\n";
    std::cout << "Closed ports:        " << closed_ports_ << "\n";
    std::cout << "Filtered ports:      " << filtered_ports_ << "\n";
    std::cout << "Duration:            " << std::fixed << std::setprecision(2)
              << duration_seconds << " seconds\n";
}

void PortScanner::write_csv() const
{
    std::ofstream file(output_file_);

    if (!file.is_open()) {
        std::cerr << "Warning: Could not write CSV file: " << output_file_ << "\n";
        return;
    }

    file << "port,state,service,banner\n";

    for (const ScanResult& result : results_) {
        file << result.port << ","
             << csv_escape(state_to_string(result.state)) << ","
             << csv_escape(result.service) << ","
             << csv_escape(result.banner) << "\n";
    }

    file.close();

    std::cout << "CSV output written to: " << output_file_ << "\n\n";
}

std::string PortScanner::csv_escape(const std::string& value) const
{
    bool must_quote = false;
    std::string escaped;

    for (char character : value) {
        if (character == '"' || character == ',' || character == '\n' || character == '\r') {
            must_quote = true;
        }

        if (character == '"') {
            escaped += "\"\"";
        }
        else {
            escaped += character;
        }
    }

    if (must_quote) {
        return "\"" + escaped + "\"";
    }

    return escaped;
}