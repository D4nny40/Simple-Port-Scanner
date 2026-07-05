#ifndef PORT_SCANNER_HPP
#define PORT_SCANNER_HPP

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

class PortScanner {
public:
    PortScanner();
    ~PortScanner();

    PortScanner(const PortScanner&) = delete;
    PortScanner& operator=(const PortScanner&) = delete;

    void set_options(
        const std::string& target,
        const std::string& port_expression,
        int max_threads,
        int timeout_seconds
    );

    void start();
    void run();

private:
    enum class PortState {
        Open,
        Closed,
        Filtered
    };

    struct ScanResult {
        std::uint16_t port;
        PortState state;
        std::string service;
        std::string banner;
    };

    void parse_ports(const std::string& port_expression);
    void resolve_target();

    bool pop_next_port(std::uint16_t& port);
    void worker_loop();

    ScanResult scan_port(std::uint16_t port);
    std::string grab_banner(SOCKET socket_handle);

    void store_result(const ScanResult& result);

    void print_result(const ScanResult& result) const;
    void print_summary() const;

    std::string service_name(std::uint16_t port) const;
    std::string state_to_string(PortState state) const;
    std::string clean_banner(const std::string& raw_banner) const;

private:
    std::string target_;
    std::string resolved_ip_;

    sockaddr_storage target_address_{};
    int target_address_length_ = 0;
    int target_family_ = AF_UNSPEC;

    std::queue<std::uint16_t> ports_;
    std::vector<ScanResult> results_;

    std::mutex queue_mutex_;
    std::mutex results_mutex_;

    int max_threads_ = 100;
    int timeout_seconds_ = 2;
    int banner_timeout_seconds_ = 1;

    int total_ports_ = 0;
    int open_ports_ = 0;
    int closed_ports_ = 0;
    int filtered_ports_ = 0;

    static const std::unordered_map<std::uint16_t, std::string> known_ports_;
};

#endif
