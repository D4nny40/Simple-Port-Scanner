#include "PortScanner.hpp"

#include <exception>
#include <iostream>
#include <string>

void print_help() {
    std::cout << "Simple Port Scanner - Version 1\n\n";

    std::cout << "Usage:\n";
    std::cout << "  simplePortScanner.exe -i <target> -p <ports> -t <threads> -e <timeout>\n\n";

    std::cout << "Options:\n";
    std::cout << "  -h, --help          Show this help message\n";
    std::cout << "  -i, --target        Target IP address or domain name\n";
    std::cout << "  -p, --ports         Ports to scan. Examples: 80, 1-1024, 22,80,443\n";
    std::cout << "  -t, --threads       Maximum number of worker threads\n";
    std::cout << "  -e, --timeout       Connection timeout in seconds\n\n";

    std::cout << "Examples:\n";
    std::cout << "  simplePortScanner.exe -i 127.0.0.1 -p 1-1024\n";
    std::cout << "  simplePortScanner.exe -i 127.0.0.1 -p 80\n";
    std::cout << "  simplePortScanner.exe -i 127.0.0.1 -p 22,80,443\n";
    std::cout << "  simplePortScanner.exe -i 127.0.0.1 -p 1-1024 -t 50 -e 3\n\n";

    std::cout << "Important:\n";
    std::cout << "  Only scan systems you own or have explicit permission to test.\n";
}

int main(int argc, char* argv[]) {
    try {
        std::string target = "127.0.0.1";
        std::string ports = "1-1024";
        int threads = 100;
        int timeout = 2;

        for (int i = 1; i < argc; ++i) {
            std::string argument = argv[i];

            if (argument == "-h" || argument == "--help") {
                print_help();
                return 0;
            } else if ((argument == "-i" || argument == "--target") && i + 1 < argc) {
                target = argv[++i];
            } else if ((argument == "-p" || argument == "--ports") && i + 1 < argc) {
                ports = argv[++i];
            } else if ((argument == "-t" || argument == "--threads") && i + 1 < argc) {
                threads = std::stoi(argv[++i]);
            } else if ((argument == "-e" || argument == "--timeout") && i + 1 < argc) {
                timeout = std::stoi(argv[++i]);
            } else {
                std::cerr << "Unknown or incomplete argument: " << argument << "\n\n";
                print_help();
                return 1;
            }
        }

        PortScanner scanner;
        scanner.set_options(target, ports, threads, timeout);
        scanner.start();
        scanner.run();

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }
}
