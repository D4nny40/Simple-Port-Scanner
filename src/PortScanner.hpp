#ifndef PORTSCANNER_HPP
#define PORTSCANNER_HPP

#ifndef NOMINMAX
#define NOMINMAX
#endif

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

enum class PortState {
    Open,
    Closed,
    Filtered
};

enum class OutputFormat {
    Csv,
    Json
};

struct ScanResult {
    int port = 0;
    PortState state = PortState::Filtered;
    std::string service = "---";
    std::string banner = "---";
};

class PortScanner {
public:
    PortScanner();
    ~PortScanner();

    void set_options(
        const std::string& target,
        const std::string& port_expression,
        int max_threads,
        int timeout_seconds,
        const std::string& output_file,
        OutputFormat output_format
    );

    void start();
    void run();

private:
    static const std::unordered_map<int, std::string> common_services;

    std::string target_ = "127.0.0.1";
    std::string port_expression_ = "1-1024";
    std::string output_file_;
    std::string resolved_ip_;
    std::string scan_time_;

    OutputFormat output_format_ = OutputFormat::Csv;

    int max_threads_ = 100;
    int timeout_seconds_ = 2;

    bool winsock_started_ = false;

    sockaddr_storage target_address_{};
    int target_address_length_ = 0;

    std::queue<int> port_queue_;
    std::vector<ScanResult> results_;

    int total_ports_ = 0;
    int open_ports_ = 0;
    int closed_ports_ = 0;
    int filtered_ports_ = 0;

    std::mutex queue_mutex_;
    std::mutex result_mutex_;

    void start_winsock();
    void stop_winsock();

    void resolve_target();
    std::vector<int> parse_ports(const std::string& expression) const;

    void worker_loop();
    ScanResult scan_port(int port) const;

    std::string grab_banner(SOCKET socket_handle) const;
    std::string clean_banner(const std::string& banner) const;

    std::string service_name(int port) const;
    std::string state_to_string(PortState state) const;
    std::string state_to_json_string(PortState state) const;

    void print_results() const;
    void print_result(const ScanResult& result) const;
    void print_summary(double duration_seconds) const;

    void write_csv() const;
    std::string csv_escape(const std::string& value) const;

    void write_json() const;
    std::string json_escape(const std::string& value) const;
    std::string current_utc_time() const;
};

#endif