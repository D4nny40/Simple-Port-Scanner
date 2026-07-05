# Simple-Port-Scanner
This program is a Windows command-line TCP port scanner written in C++.  Its job is to check a target machine and identify selected TCP ports states. It also attempts basic banner grabbing from open services.  This version is designed for portfoilo and should not be used for offensive purposes. 

## Current Version

V2.0.0 - CSV Output Release

Version 2 adds CSV output using `-o output.csv`.

## Prerequisites/Requirements to use this project and why they are needed
| Requirement | Why it is needed |
|---|---|
| Windows 10 or Windows 11 | uses WinSock, which is the Windows socket API |
| CMake 3.16 or newer | Used to configure and generate the build files |
| Visual Studio C++ Build Tools | Provides the MSVC C++ compiler |
| Windows SDK | Provides Windows networking headers and libraries |
| PowerShell or Command Prompt | Used to run the build and scanner commands |
| C++20-compatible compiler | The project is configured to use C++20 |

## How to Use
### 1. Build the project
Using powershell, you need to go to the directory the code is in and build the app using this as an example.
```
cd C:\Users\Whatever your username is\Downloads\Simple-Port-Scanner-main\Simple-Port-Scanner-main
```
Then you need to build the app using these commands.
```
mkdir build
cd build
cmake ..
cmake --build . --config Debug
```
After building, it should be located in Build/debug/simplePortScanner.exe. To get started simply type 
```
.\Debug\simplePortScanner.exe --help
```
Which will give you all the help you need to use the scanner.

To utilise Version 2.0.0's feature you can use this command (change depending on IP):
```
.\Debug\simplePortScanner.exe -i 127.0.0.1 -p 1-100 -o results.csv
```
Which will give you the results in a .csv file in the build directory. 

To utilise Version 2.1.0's feature you can use a commmand like this (change depending on IP):
```
.\Debug\simplePortScanner.exe -i 127.0.0.1 -p 1-100 -o output.json --format json
```
This will output the scan results as a .json file in the build directory.

## Version History

### V1.0.0 - Initial Working Release
- Added target selection
- Added port range parsing
- Added open, closed, and filtered state detection
- Added basic service-name identification
- Added passive banner grabbing
- Added multi-threaded scanning

### V2.0.0 - CSV Output Release
- Added `-o output.csv` which will allow the scan to be output to a `.csv` file in the build directory.
- Added `--output output.csv` for long form options
- Added CSV output format: `port,state,service,banner`
- Added CSV escaping for commas, quotes, and newlines in banner text
- Updated help menu examples
- Updated README usage instructions

### V2.1.0 - JSON Exportation Feature Release
- Added  `-o output.json` which will allow the scan to be output to a `.json` file in the build directory.
- Added  `--output output.json` for long form options.
- Added  `--format json` allowing it to be distinguished over CSV.
- Updated help menu examples
- Updated README usage instructions

## Potential Improvements in the future

- Output Improvement and Potential Exportation for later analysis. - **Completed**
- Utilising the original idea's design by using Boost.
- Better Scanner behaviour using async
- Progress Indication
- Multiple Host Scanning capabilites
- Service Version Detection
- Potential GUI Implementation

## Credit to https://github.com/topics/cybersecurity-projects for the idea

In the original idea, the use of Boost.Asio with asynchronous socket operations, timers, and an event-loop based architecture was suggested, this was changed to use the native Windows WinSock API instead. This was done because the initial development environment had dependency setup issues with Boost and vcpkg. Rather than blocking the whole project at the dependency stage, the first version focuses on building and testing the core scanner behaviour first.
## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
