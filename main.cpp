#include "PortScanner.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

void print_help()
{
    std::cout << "Simple Port Scanner - Version 2\n";
    std::cout << "================================\n\n";

    std::cout << "Usage:\n";
    std::cout << "  simplePortScanner.exe [options]\n\n";

    std::cout << "Options:\n";
    std::cout << "  -h, --help              Show this help menu\n";
    std::cout << "  -i, --target <target>   Target IP address or domain name\n";
    std::cout << "  -p, --ports <ports>     Ports to scan, e.g. 80, 1-1024, 22,80,443\n";
    std::cout << "  -t, --threads <num>     Number of worker threads\n";
    std::cout << "  -e, --timeout <sec>     Timeout in seconds\n";
    std::cout << "  -o, --output <file>     Write scan results to a CSV file\n\n";

    std::cout << "Examples:\n";
    std::cout << "  simplePortScanner.exe -i 127.0.0.1 -p 1-100\n";
    std::cout << "  simplePortScanner.exe -i 127.0.0.1 -p 22,80,443\n";
    std::cout << "  simplePortScanner.exe -i 127.0.0.1 -p 1-1024 -t 50 -e 3\n";
    std::cout << "  simplePortScanner.exe -i 127.0.0.1 -p 1-1024 -o results.csv\n\n";

    std::cout << "CSV output format:\n";
    std::cout << "  port,state,service,banner\n\n";

    std::cout << "Important:\n";
    std::cout << "  Only scan systems that you own or have permission to test.\n";
}

std::string require_value(int& index, int argc, char* argv[], const std::string& option)
{
    if (index + 1 >= argc) {
        throw std::runtime_error("Missing value after " + option);
    }

    ++index;
    return argv[index];
}

int main(int argc, char* argv[])
{
    std::string target = "127.0.0.1";
    std::string ports = "1-1024";
    int threads = 100;
    int timeout = 2;
    std::string output_file;

    try {
        for (int i = 1; i < argc; ++i) {
            std::string argument = argv[i];

            if (argument == "-h" || argument == "--help") {
                print_help();
                return 0;
            }
            else if (argument == "-i" || argument == "--target") {
                target = require_value(i, argc, argv, argument);
            }
            else if (argument == "-p" || argument == "--ports") {
                ports = require_value(i, argc, argv, argument);
            }
            else if (argument == "-t" || argument == "--threads") {
                threads = std::stoi(require_value(i, argc, argv, argument));
            }
            else if (argument == "-e" || argument == "--timeout") {
                timeout = std::stoi(require_value(i, argc, argv, argument));
            }
            else if (argument == "-o" || argument == "--output") {
                output_file = require_value(i, argc, argv, argument);
            }
            else {
                std::cerr << "Unknown option: " << argument << "\n\n";
                print_help();
                return 1;
            }
        }

        PortScanner scanner;
        scanner.set_options(target, ports, threads, timeout, output_file);
        scanner.start();
        scanner.run();
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n\n";
        print_help();
        return 1;
    }

    return 0;
}