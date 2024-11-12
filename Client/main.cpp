// Tomer Rosenfeld 314626425
#include <iostream>
#include <fstream>
#include <string>
#include <boost/asio.hpp>
#include "Client.h"

// Reads server IP and port from transfer.info
// Returns false if file missing or invalid
bool readServerInfo(std::string& ip, int& port) {
    std::ifstream file("transfer.info");
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open transfer.info" << std::endl;
        return false;
    }

    std::string line;
    if (std::getline(file, line)) {
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            ip = line.substr(0, colonPos);
            port = std::stoi(line.substr(colonPos + 1));
            return true;
        }
    }

    std::cerr << "Error: Invalid format in transfer.info" << std::endl;
    return false;
}

// 1. Reads server configuration
// 2. Creates client instance
// 3. Initiates connection process
// 4. Runs IO context for async operations
int main() {
    std::string serverIP;
    int serverPort;

    if (!readServerInfo(serverIP, serverPort)) {
        return 1;
    }

    try {
        boost::asio::io_context io_context;
        auto client = std::make_shared<Client>(io_context, serverIP, serverPort);

        // Enable test mode for CRC mismatch:
        //client->enableRandomCorruption(3); // Will corrupt 1-3 random bytes

        client->start();
        std::cout << "Client initialized. Connecting to the server..." << std::endl;
        client->initiateConnection();
        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

	// Wait for the user to press a key before exiting - this is to prevent the console from closing immediately for submitting the assignment
    std::cout << "Client closed connection. Press Enter to close...";
    std::cin.get(); // Wait for Enter key
    return 0;
}