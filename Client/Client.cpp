// Client.cpp - Implementation of client functionality.
// Tomer Rosenfeld 314626425
#include "Client.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>
#include <boost/endian/conversion.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/oaep.h>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>


Client::Client(boost::asio::io_context& io_context, const std::string& server_ip, int server_port)
    : io_context_(io_context),
    socket_(io_context),
    server_ip_(server_ip),
    server_port_(server_port),
    is_registered_(false),
    keys_generated_(false),
    random_corruption_enabled_(false),
    max_corruption_bytes_(MAX_CORRUPTION_BYTES) {
    std::fill(client_id_.begin(), client_id_.end(), 0);
    initializeRNG();
}


void Client::start() {
    std::cout << "Client::start() method called" << std::endl;
    try {
        if (!readTransferInfo()) {
            std::cerr << "Failed to read transfer.info. Cannot proceed." << std::endl;
            return;
        }

        // Try to load existing client info
        bool existing_client = loadClientInfo();

        if (!existing_client) {
            std::cout << "Starting registration process with name from transfer.info." << std::endl;
            generateRSAKeys();
            storePrivateKey();
        }
        else {
            std::cout << "Found existing client info. Loading stored RSA key..." << std::endl;
            if (!loadPrivateKeyFromFile("priv.key")) {
                std::cerr << "Failed to load private key. Cannot proceed." << std::endl;
                return;
            }
            keys_generated_ = true;
        }

        std::cout << "Client initialization completed." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Caught exception in start method: " << e.what() << std::endl;
    }
    std::cout << "Client::start() method completed" << std::endl;
}


void Client::initiateConnection() {
    std::cout << "Initiating connection to server..." << std::endl;
    if (!socket_.is_open()) {
        connect();
    }
    else {
        std::cout << "Already connected to server." << std::endl;
    }
}

// Establishes TCP connection to server
// Initiates registration or reconnection based on client state
void Client::connect() {
    std::cout << "Client::connect() method called" << std::endl;
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(server_ip_), server_port_);
    std::cout << "Endpoint created: " << server_ip_ << ":" << server_port_ << std::endl;

    std::cout << "Initiating async_connect..." << std::endl;
    socket_.async_connect(endpoint,
        [this](const boost::system::error_code& error) {
            if (!error) {
                std::cout << "Connected to server." << std::endl;
                if (!is_registered_) {
                    std::cout << "Sending registration request..." << std::endl;
                    sendRegistrationRequest();
                }
                else {
                    std::cout << "Sending reconnection request..." << std::endl;
                    sendReconnectionRequest();
                }
            }
            else {
                std::cerr << "Connection failed: " << error.message() << std::endl;
            }
        });
    std::cout << "async_connect initiated" << std::endl;
}

// Sends initial registration request to server
// Includes client name and waits for ID assignment
void Client::sendReconnectionRequest() {
    RequestHeader request;
    std::copy(client_id_.begin(), client_id_.end(), request.client_id.begin());
    request.version = 3;
    request.code = boost::endian::native_to_little(static_cast<uint16_t>(RequestCode::Reconnect));

    // Prepare name payload
    std::vector<char> name_buffer(MAX_NAME_LENGTH, 0);
    strncpy_s(name_buffer.data(), MAX_NAME_LENGTH, client_name_.c_str(), _TRUNCATE);
    request.payload_size = boost::endian::native_to_little(static_cast<uint32_t>(strlen(name_buffer.data()) + 1));

    std::cout << "Sending reconnection request for client: " << client_name_ << std::endl;

    // Send header and name
    boost::system::error_code ec;
    boost::asio::write(socket_, boost::asio::buffer(&request, sizeof(request)), ec);
    if (!ec) {
        boost::asio::write(socket_, boost::asio::buffer(name_buffer.data(), strlen(name_buffer.data()) + 1), ec);
        if (!ec) {
            std::cout << "Reconnection request sent successfully" << std::endl;
            readResponse();
        }
    }

    if (ec) {
        std::cerr << "Failed to send reconnection request: " << ec.message() << std::endl;
        closeConnection();
    }
}

// Attempts to reconnect with existing client ID
// Used when client has previously registered
void Client::sendRegistrationRequest() {
    RegistrationRequest request;
    std::copy(client_id_.begin(), client_id_.end(), request.header.client_id.begin());
    request.header.version = 3;
    request.header.code = boost::endian::native_to_little(static_cast<uint16_t>(RequestCode::Register));

    strncpy_s(request.name, sizeof(request.name), client_name_.c_str(), _TRUNCATE);

    request.header.payload_size = boost::endian::native_to_little(static_cast<uint32_t>(strlen(request.name) + 1));

    std::cout << "Sending registration request:" << std::endl;
    std::cout << "Version: " << static_cast<int>(request.header.version) << std::endl;
    std::cout << "Code: " << boost::endian::little_to_native(request.header.code) << std::endl;
    std::cout << "Payload size: " << boost::endian::little_to_native(request.header.payload_size) << std::endl;
    std::cout << "Name: " << request.name << std::endl;

    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(&request, sizeof(RequestHeader) + strlen(request.name) + 1),
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec) {
                std::cout << "Registration request sent. Bytes sent: " << length << std::endl;
                readResponse();
            }
            else {
                std::cerr << "Send failed: " << ec.message() << std::endl;
            }
        });
}

// Asynchronously reads server response headers
// 1. Reads fixed-size response header
// 2. Converts from network byte order
// 3. Routes to appropriate handler based on response code
// 4. Handles various responses: registration, reconnection, file transfer, etc.
void Client::readResponse() {
    auto self(shared_from_this());
    boost::asio::async_read(socket_, response_,
        boost::asio::transfer_exactly(sizeof(ResponseHeader)),
        [this, self](boost::system::error_code ec, std::size_t /*length*/) {
            if (!ec) {
                ResponseHeader header;
                std::istream response_stream(&response_);
                response_stream.read(reinterpret_cast<char*>(&header), sizeof(header));

                header.code = boost::endian::little_to_native(header.code);
                header.payload_size = boost::endian::little_to_native(header.payload_size);

                std::cout << "Received server response code: " << header.code << std::endl;

                switch (header.code) {
                case static_cast<uint16_t>(ResponseCode::RegisterSuccess):
                    handleRegistrationResponse();
                    break;
                case static_cast<uint16_t>(ResponseCode::ReconnectApproved):
                    handleReconnectionResponse();
                    break;
                case static_cast<uint16_t>(ResponseCode::PublicKeyReceived):
                    readPublicKeyResponse();
                    break;
                case static_cast<uint16_t>(ResponseCode::FileReceived):
                    std::cout << "File received by server, checking CRC..." << std::endl;
                    handleFileReceivedResponse();
                    break;
                case static_cast<uint16_t>(ResponseCode::MessageReceived):
                    std::cout << "Server acknowledged message receipt" << std::endl;
                    break;
                case static_cast<uint16_t>(ResponseCode::ReconnectDenied):
                    std::cerr << "Server denied reconnection. Please check registration." << std::endl;
                    closeConnection();
                    break;
                default:
                    std::cerr << "Unexpected response from server: " << header.code << std::endl;
                    closeConnection();
                    break;
                }
            }
            else {
                std::cerr << "Error reading server response: " << ec.message() << std::endl;
                closeConnection();
            }
        });
}

// Handles server's reconnection approval:
// 1. Sets TCP_NODELAY for better performance
// 2. Reads and validates response header
// 3. Receives new encrypted AES key
// 4. Decrypts key and prepares for file transfer
void Client::handleReconnectionResponse() {
    std::cout << "Handling reconnection response..." << std::endl;

    try {
        // Set TCP_NODELAY
        boost::asio::ip::tcp::no_delay no_delay_option(true);
        socket_.set_option(no_delay_option);

        std::cout << "Reading header..." << std::endl;

        // Read all 7 bytes of the header at once
        std::array<uint8_t, 7> header;
        boost::system::error_code ec;

        size_t header_read = boost::asio::read(
            socket_,
            boost::asio::buffer(header),
            boost::asio::transfer_exactly(7),
            ec
        );

        if (ec || header_read != 7) {
            throw std::runtime_error("Failed to read header: " + ec.message());
        }

        // Print raw bytes
        std::cout << "Raw header bytes: ";
        for (uint8_t b : header) {
            printf("%02X ", b);
        }
        std::cout << std::endl;

        // Parse header - assuming little endian as per struct.pack('<BHI')
        uint8_t version = header[0];
        uint16_t code = *reinterpret_cast<uint16_t*>(&header[1]);  // 2 bytes
        uint32_t size = *reinterpret_cast<uint32_t*>(&header[3]);  // 4 bytes

        // Fix endianness if needed
        code = boost::endian::little_to_native(code);
        size = boost::endian::little_to_native(size);

        std::cout << "Parsed values:" << std::endl;
        std::cout << "Version: " << (int)version << " (expected: 3)" << std::endl;
        std::cout << "Code: " << code << " (expected: 1605)" << std::endl;
        std::cout << "Size: " << size << " (expected: 128)" << std::endl;

        if (version != 3 || code != static_cast<uint16_t>(ResponseCode::ReconnectApproved) || size != 128) {
            throw std::runtime_error("Invalid header values received");
        }

        // Read encrypted key
        std::cout << "Reading encrypted AES key..." << std::endl;
        std::vector<uint8_t> encrypted_key(128);
        size_t key_read = boost::asio::read(
            socket_,
            boost::asio::buffer(encrypted_key),
            boost::asio::transfer_exactly(128),
            ec
        );

        if (ec || key_read != 128) {
            throw std::runtime_error("Failed to read encrypted key: " + ec.message());
        }

        std::cout << "Received encrypted AES key (" << key_read << " bytes)" << std::endl;

        if (!decryptAESKey(encrypted_key)) {
            throw std::runtime_error("Failed to decrypt AES key");
        }

        std::cout << "Successfully decrypted AES key, proceeding with file transfer" << std::endl;
        sendFile();
    }
    catch (const std::exception& e) {
        std::cerr << "Error in handleReconnectionResponse: " << e.what() << std::endl;
        closeConnection();
    }
}

// Processes successful registration response:
// 1. Reads assigned client ID
// 2. Updates client state
// 3. Stores credentials to me.info
// 4. Initiates public key exchange
void Client::handleRegistrationResponse() {
    auto self(shared_from_this());
    boost::asio::async_read(socket_, boost::asio::buffer(client_id_),
        [this, self](boost::system::error_code ec, std::size_t /*length*/)
        {
            if (!ec) {
                std::cout << "Registration successful." << std::endl;
                std::cout << "Received client ID: " << clientIdToString() << std::endl;
                is_registered_ = true;
                storeClientInfo();  // Save the new client ID

                // Continue with the next step - sending public key
                std::cout << "Proceeding to send public key..." << std::endl;
                sendPublicKey();
            }
            else {
                std::cerr << "Failed to read client ID: " << ec.message() << std::endl;
                closeConnection();
            }
        });
}

// Generates new RSA key pair for secure communication
// Creates 1024-bit keys using CryptoPP library
void Client::generateRSAKeys() {
    std::cout << "Entering generateRSAKeys()" << std::endl;
    try {
        CryptoPP::AutoSeededRandomPool rng;
        std::cout << "Initializing private key..." << std::endl;
        private_key_.Initialize(rng, 1024);
        std::cout << "Private key initialized" << std::endl;

        std::cout << "Creating public key from private key..." << std::endl;
        public_key_ = CryptoPP::RSA::PublicKey(private_key_);
        std::cout << "Public key created" << std::endl;

        keys_generated_ = true;
        std::cout << "RSA key pair generated successfully." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error in generateRSAKeys: " << e.what() << std::endl;
        keys_generated_ = false;
    }
    std::cout << "Exiting generateRSAKeys()" << std::endl;
}

bool Client::loadRSAKeys() {
    return loadPrivateKeyFromFile("me.info") || loadPrivateKeyFromFile("priv.key");
}

// Sends client's public RSA key to server:
// 1. Serializes public key
// 2. Constructs request header
// 3. Sends key synchronously
// 4. Awaits server's AES key response
void Client::sendPublicKey() {
    std::cout << "sendPublicKey() called" << std::endl;
    if (!keys_generated_) {
        std::cerr << "RSA keys have not been generated." << std::endl;
        return;
    }

    try {
        // Serialize the public key
        CryptoPP::ByteQueue queue;
        public_key_.Save(queue);
        std::string public_key_str;
        CryptoPP::StringSink ss(public_key_str);
        queue.CopyTo(ss);

        std::cout << "Public key serialized. Length: " << public_key_str.size() << " bytes" << std::endl;

        // Prepare the request
        RequestHeader request;
        std::copy(client_id_.begin(), client_id_.end(), request.client_id.begin());
        request.version = 3;
        request.code = boost::endian::native_to_little(static_cast<uint16_t>(RequestCode::SendPublicKey));
        request.payload_size = boost::endian::native_to_little(static_cast<uint32_t>(public_key_str.size()));

        std::cout << "Sending public key request header" << std::endl;

        // Send the request header synchronously
        boost::system::error_code ec;
        size_t header_bytes_sent = boost::asio::write(socket_, boost::asio::buffer(&request, sizeof(request)), ec);

        if (ec) {
            std::cerr << "Failed to send public key request header: " << ec.message() << std::endl;
            closeConnection();
            return;
        }

        std::cout << "Public key request header sent. Bytes sent: " << header_bytes_sent << std::endl;
        std::cout << "Sending public key..." << std::endl;

        // Send the public key synchronously
        size_t key_bytes_sent = boost::asio::write(socket_, boost::asio::buffer(public_key_str), ec);

        if (ec) {
            std::cerr << "Failed to send public key: " << ec.message() << std::endl;
            closeConnection();
            return;
        }

        std::cout << "Public key sent. Bytes sent: " << key_bytes_sent << std::endl;
        std::cout << "Waiting for acknowledgment..." << std::endl;

        readPublicKeyResponse();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in sendPublicKey: " << e.what() << std::endl;
        closeConnection();
    }
    catch (...) {
        std::cerr << "Unknown exception in sendPublicKey" << std::endl;
        closeConnection();
    }
    std::cout << "sendPublicKey() completed" << std::endl;
}

// Processes server's response to public key:
// 1. Reads response header
// 2. Receives encrypted AES key
// 3. Decrypts and stores AES key
// 4. Initiates file transfer if successful
void Client::readPublicKeyResponse() {
    auto self(shared_from_this());
    boost::asio::async_read(socket_, response_, boost::asio::transfer_exactly(sizeof(ResponseHeader)),
        [this, self](boost::system::error_code ec, std::size_t /*length*/)
        {
            if (!ec) {
                ResponseHeader header;
                std::istream response_stream(&response_);
                response_stream.read(reinterpret_cast<char*>(&header), sizeof(header));

                header.code = boost::endian::little_to_native(header.code);
                header.payload_size = boost::endian::little_to_native(header.payload_size);

                std::cout << "\nReceived server response:" << std::endl;
                std::cout << "Response code: " << header.code << std::endl;
                std::cout << "Payload size: " << header.payload_size << std::endl;

                if (header.code == static_cast<uint16_t>(ResponseCode::PublicKeyReceived)) {
                    if (header.payload_size > 0) {
                        std::cout << "Server indicates encrypted AES key in response." << std::endl;
                        auto encrypted_aes_key = std::make_shared<std::vector<uint8_t>>(header.payload_size);

                        boost::asio::async_read(
                            socket_,
                            boost::asio::buffer(*encrypted_aes_key),
                            [this, self, encrypted_aes_key](boost::system::error_code ec, std::size_t length)
                            {
                                if (!ec) {
                                    std::cout << "Successfully received encrypted AES key data." << std::endl;
                                    std::cout << "Encrypted AES key size: " << length << " bytes" << std::endl;

                                    if (decryptAESKey(*encrypted_aes_key)) {
                                        std::cout << "Successfully decrypted and stored AES key." << std::endl;
                                        // Start file transfer after successful AES key reception
                                        std::cout << "Starting file transfer..." << std::endl;
                                        sendFile();
                                    }
                                    else {
                                        std::cerr << "Failed to decrypt AES key." << std::endl;
                                        closeConnection();
                                    }
                                }
                                else {
                                    std::cerr << "Failed to read encrypted AES key: " << ec.message() << std::endl;
                                    closeConnection();
                                }
                            });
                    }
                    else {
                        std::cerr << "Warning: Public key received response but no AES key payload" << std::endl;
                        closeConnection();
                    }
                }
                else {
                    std::cerr << "Unexpected response code: " << header.code << std::endl;
                    closeConnection();
                }
            }
            else {
                std::cerr << "Failed to read response header: " << ec.message() << std::endl;
                closeConnection();
            }
        });
}

// Gracefully closes client connection:
// 1. Shuts down socket both ways
// 2. Closes socket
// 3. Cleans up resources
// 4. Handles shutdown errors
void Client::closeConnection() {
    std::cout << "closeConnection() called" << std::endl;
    boost::system::error_code ec;

    if (socket_.is_open()) {
        std::cout << "Socket is open. Attempting to shut down..." << std::endl;
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        if (ec) {
            std::cerr << "Error during socket shutdown: " << ec.message() << std::endl;
        }
        else {
            std::cout << "Socket shut down successfully" << std::endl;
        }

        std::cout << "Attempting to close socket..." << std::endl;
        socket_.close(ec);
        if (ec) {
            std::cerr << "Error during socket close: " << ec.message() << std::endl;
        }
        else {
            std::cout << "Socket closed successfully" << std::endl;
        }
    }
    else {
        std::cout << "Socket was already closed" << std::endl;
    }

    std::cout << "closeConnection() completed" << std::endl;
}

// Saves RSA private key to both me.info and priv.key
// Includes client name and ID in me.info
void Client::storePrivateKey() {
    std::cout << "Entering storePrivateKey()" << std::endl;
    try {
        // Generate Base64 encoded key
        std::string encoded_key;
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_key), false); // false = no line breaks
        private_key_.DEREncode(encoder);
        encoder.MessageEnd();

        // First construct the complete content for me.info
        std::stringstream me_info_content;
        me_info_content << client_name_ << "\n"
            << clientIdToString() << "\n"
            << encoded_key;

        // Write to priv.key first
        {
            std::ofstream priv_file("priv.key", std::ios::binary | std::ios::trunc);
            if (!priv_file) {
                throw std::runtime_error("Failed to open priv.key for writing");
            }
            priv_file.write(encoded_key.c_str(), encoded_key.length());
            priv_file.flush();
            if (priv_file.fail()) {
                throw std::runtime_error("Failed to write to priv.key");
            }
            priv_file.close();
            std::cout << "Private key saved to priv.key" << std::endl;
        }

        // Then write to me.info
        {
            std::ofstream me_file("me.info", std::ios::trunc);
            if (!me_file) {
                throw std::runtime_error("Failed to open me.info for writing");
            }
            me_file.write(me_info_content.str().c_str(), me_info_content.str().length());
            me_file.flush();
            if (me_file.fail()) {
                throw std::runtime_error("Failed to write to me.info");
            }
            me_file.close();
            std::cout << "Private key saved to me.info" << std::endl;
        }

        // Verify the files were written correctly
        std::ifstream verify_me("me.info");
        std::string content((std::istreambuf_iterator<char>(verify_me)),
            std::istreambuf_iterator<char>());
        if (content != me_info_content.str()) {
            throw std::runtime_error("Verification failed: me.info content mismatch");
        }
        verify_me.close();
    }
    catch (const std::exception& e) {
        std::cerr << "Error in storePrivateKey: " << e.what() << std::endl;
        throw;
    }
    std::cout << "Exiting storePrivateKey()" << std::endl;
}

// Saves RSA private key to file:
// 1. Encodes key in Base64 format
// 2. Writes to specified file
// 3. Verifies written data
// 4. Handles write errors
void Client::storePrivateKeyToFile(std::ofstream& file) {
    CryptoPP::Base64Encoder encoder(new CryptoPP::FileSink(file));
    private_key_.DEREncode(encoder);
    encoder.MessageEnd();
}

void Client::storePrivateKeyToFile(const std::string& filename) {
    std::cout << "Entering storePrivateKeyToFile for " << filename << std::endl;
    try {
        // Encode the key to a string stream
        std::stringstream keyStream;
        CryptoPP::Base64Encoder encoder(new CryptoPP::FileSink(keyStream));
        private_key_.DEREncode(encoder);
        encoder.MessageEnd();
        std::string encoded_key = keyStream.str();
        std::cout << "Key encoded successfully. Encoded key length: " << encoded_key.length() << std::endl;

        // Open file in overwrite mode
        std::ofstream file(filename, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            std::cerr << "Failed to open " << filename << " for writing" << std::endl;
            return;
        }
        std::cout << "File opened successfully: " << filename << std::endl;

        // Write the encoded key to the file
        file << encoded_key << std::endl;
        file.flush();
        file.close();

        if (file.fail()) {
            std::cerr << "Error occurred while writing to or closing the file" << std::endl;
            return;
        }

        std::cout << "Private key successfully written to " << filename << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error in storePrivateKeyToFile for " << filename << ": " << e.what() << std::endl;
    }
    std::cout << "Exiting storePrivateKeyToFile for " << filename << std::endl;
}

void Client::loadPrivateKey() {
    std::cout << "Attempting to load private key..." << std::endl;

    // First try me.info
    if (loadPrivateKeyFromFile("me.info")) {
        std::cout << "Successfully loaded private key from me.info" << std::endl;
        return;
    }

    // If that fails, try priv.key
    if (loadPrivateKeyFromFile("priv.key")) {
        std::cout << "Successfully loaded private key from priv.key" << std::endl;
        return;
    }

    throw std::runtime_error("Could not load private key from any source");
}

// Loads RSA private key from storage:
// 1. Handles both me.info and priv.key formats
// 2. Strips whitespace and decodes Base64
// 3. Reconstructs RSA key object
// 4. Generates corresponding public key
bool Client::loadPrivateKeyFromFile(const std::string& filename) {
    std::cout << "Attempting to load private key from " << filename << std::endl;
    try {
        std::string key_data;
        std::ifstream file(filename, std::ios::binary);

        if (!file.is_open()) {
            throw std::runtime_error("Could not open " + filename);
        }

        if (filename == "me.info") {
            // Skip first two lines
            std::string line;
            std::getline(file, line); // name
            std::getline(file, line); // UUID

            // Read the rest as the key
            std::stringstream key_stream;
            key_stream << file.rdbuf();
            key_data = key_stream.str();
        }
        else { // priv.key
            std::stringstream buffer;
            buffer << file.rdbuf();
            key_data = buffer.str();
        }

        if (key_data.empty()) {
            throw std::runtime_error("No key data found");
        }

        // Remove any whitespace
        key_data.erase(std::remove_if(key_data.begin(), key_data.end(),
            [](char c) { return std::isspace(c); }), key_data.end());

        // Decode and import the key
        CryptoPP::StringSource ss(key_data, true, new CryptoPP::Base64Decoder);
        private_key_.BERDecode(ss);
        public_key_ = CryptoPP::RSA::PublicKey(private_key_);
        keys_generated_ = true;

        std::cout << "Successfully loaded key from " << filename << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error loading key from " << filename << ": " << e.what() << std::endl;
        return false;
    }
}

// Decrypts AES key received from server using private RSA key
// Returns success/failure of decryption
bool Client::decryptAESKey(const std::vector<uint8_t>& encrypted_key) {
    try {
        std::cout << "Starting AES key decryption..." << std::endl;

        CryptoPP::AutoSeededRandomPool rng;

        // Create decryptor object
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(private_key_);

        // Calculate required size for decrypted key
        size_t decrypted_length = decryptor.MaxPlaintextLength(encrypted_key.size());

        // Prepare buffer for decrypted key
        std::vector<uint8_t> decrypted_key(decrypted_length);

        // Decrypt the AES key
        CryptoPP::DecodingResult result = decryptor.Decrypt(rng,
            encrypted_key.data(),
            encrypted_key.size(),
            decrypted_key.data());

        if (result.isValidCoding) {
            std::cout << "AES key decrypted successfully. Length: " << result.messageLength << " bytes" << std::endl;

            // Store the decrypted AES key
            aes_key_ = std::vector<uint8_t>(decrypted_key.begin(), decrypted_key.begin() + result.messageLength);
            aes_key_received_ = true;

            return true;
        }
        else {
            std::cerr << "Failed to decrypt AES key: invalid coding" << std::endl;
            return false;
        }
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ error while decrypting AES key: " << e.what() << std::endl;
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "Standard error while decrypting AES key: " << e.what() << std::endl;
        return false;
    }
}

// Manages client credential storage:
// 1. Reads existing private key if present
// 2. Updates client name and ID
// 3. Writes to me.info
// 4. Preserves existing key data
void Client::storeClientInfo() {
    std::cout << "Entering storeClientInfo()" << std::endl;
    try {
        // Read existing key if present
        std::string private_key_data;
        std::ifstream infile("me.info");
        std::string line;
        int line_count = 0;
        while (std::getline(infile, line)) {
            if (line_count == 2) { // Third line is the private key
                private_key_data = line;
                break;
            }
            line_count++;
        }
        infile.close();

        // Write new information
        std::ofstream file("me.info", std::ios::out | std::ios::trunc);
        if (file.is_open()) {
            // Write client name and ID
            file << client_name_ << std::endl;
            file << clientIdToString() << std::endl;

            // Write back the private key if it exists
            if (!private_key_data.empty()) {
                file << private_key_data << std::endl;
            }

            file.close();
            std::cout << "Client information saved to me.info" << std::endl;
        }
        else {
            std::cerr << "Unable to open me.info for writing" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error in storeClientInfo: " << e.what() << std::endl;
    }
    std::cout << "Exiting storeClientInfo()" << std::endl;
}

// Loads existing client information from me.info
// Returns true if successful, false if new client
bool Client::loadClientInfo() {
    std::ifstream file("me.info");
    if (file.is_open()) {
        std::string id_str;
        if (std::getline(file, client_name_) && std::getline(file, id_str)) {
            for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
                std::string byte_str = id_str.substr(i * 2, 2);
                client_id_[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
            }
            is_registered_ = true;
            std::cout << "Client information loaded from me.info" << std::endl;
            return true;
        }
    }
    return false;
}

std::string Client::clientIdToString() const {
    std::stringstream ss;
    for (const auto& byte : client_id_) {
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte);
    }
    return ss.str();
}

bool Client::readTransferInfo() {
    std::ifstream file("transfer.info");
    if (!file.is_open()) {
        std::cerr << "Unable to open transfer.info" << std::endl;
        return false;
    }

    std::string line;
    int line_number = 0;
    while (std::getline(file, line) && line_number < 3) {
        switch (line_number) {
        case 1:
            client_name_ = line;
            break;
        case 2:
            file_path_ = line;
            break;
        }
        line_number++;
    }

    if (client_name_.empty() || file_path_.empty()) {
        std::cerr << "Invalid format in transfer.info" << std::endl;
        return false;
    }

    std::cout << "Read from transfer.info - Name: " << client_name_ << ", File: " << file_path_ << std::endl;
    return true;
}

void Client::sendMessage(const std::string& message) {
    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(message),
        [this, self, message](boost::system::error_code ec, std::size_t /*length*/)
        {
            if (!ec) {
                std::cout << "Message sent: " << message << std::endl;
                readResponse();
            }
            else {
                std::cerr << "Send failed: " << ec.message() << std::endl;
            }
        });
}

// Main file transfer function:
// 1. Reads file content
// 2. Encrypts using AES
// 3. Sends to server in chunks
// 4. Handles CRC verification
void Client::sendFile() {
    try {
        std::cout << "Starting file transfer process..." << std::endl;

        // Reset retry counter at the start of new file transfer
        retry_count_ = 0;

        // Read file content
        std::vector<uint8_t> file_content = readFileContent(file_path_);
        if (file_content.empty()) {
            std::cerr << "Failed to read file content" << std::endl;
            return;
        }
        std::cout << "File read successfully. Size: " << file_content.size() << " bytes" << std::endl;

        //// Corrupt the data in test mode BEFORE encryption
        //if (test_mode_corrupt_data_) {
        //    std::cout << "TEST MODE: Corrupting file data before encryption..." << std::endl;
        //    if (file_content.size() >= 3) {
        //        file_content[0] ^= 0xFF;  // Flip bits in first byte
        //        file_content[1] ^= 0xFF;  // Flip bits in second byte
        //        file_content[2] ^= 0xFF;  // Flip bits in third byte
        //        std::cout << "Modified first three bytes of original file" << std::endl;
        //    }
        //}

        // Encrypt file content
        std::vector<uint8_t> encrypted_content = encryptFileContent(file_content);
        if (encrypted_content.empty()) {
            std::cerr << "Failed to encrypt file content" << std::endl;
            return;
        }
        std::cout << "File encrypted successfully. Size: " << encrypted_content.size() << " bytes" << std::endl;

        // Get filename from path
        std::string filename = file_path_.substr(file_path_.find_last_of("/\\") + 1);

        // Send encrypted file
        sendEncryptedFile(filename, encrypted_content);
    }
    catch (const std::exception& e) {
        std::cerr << "Error in sendFile: " << e.what() << std::endl;
    }
}

// Reads file from disk into memory:
// 1. Opens file in binary mode
// 2. Determines file size
// 3. Reads entire content into vector
// 4. Handles read errors and file accessibility
std::vector<uint8_t> Client::readFileContent(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return std::vector<uint8_t>();
    }

    // Get file size
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read file content
    std::vector<uint8_t> content(file_size);
    file.read(reinterpret_cast<char*>(content.data()), file_size);

    if (!file) {
        std::cerr << "Failed to read file content" << std::endl;
        return std::vector<uint8_t>();
    }

    return content;
}

// Encrypts file data using AES in CBC mode with zero IV
// Returns encrypted data as byte vector
std::vector<uint8_t> Client::encryptFileContent(const std::vector<uint8_t>& file_content) {
    try {
        // Create a zero IV (as specified in the project requirements)
        CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
        std::memset(iv, 0, CryptoPP::AES::BLOCKSIZE);

        // Prepare the encryption objects
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(aes_key_.data(), aes_key_.size(), iv);

        // Encrypt the content
        std::string cipher;
        CryptoPP::StringSource ss(
            (const CryptoPP::byte*)file_content.data(),
            file_content.size(),
            true,
            new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(cipher))
        );

        // Convert to vector
        return std::vector<uint8_t>(cipher.begin(), cipher.end());
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
        return std::vector<uint8_t>();
    }
}

// Handles the complete file transfer process:
// 1. Prepares file metadata (size, name, etc.)
// 2. Sends request header
// 3. Sends file info structure
// 4. Chunks and sends encrypted content
// 5. Manages transmission errors
void Client::sendEncryptedFile(const std::string& filename, const std::vector<uint8_t>& encrypted_content) {
    try {
        std::cout << "Preparing to send encrypted file..." << std::endl;

        // Create a copy of the content to ensure it stays valid
        std::vector<uint8_t> content_copy(encrypted_content);

        // Store the original content for CRC verification
        last_sent_content_ = readFileContent(file_path_);

		// Apply random corruption if enabled (for testing purposes)
        corruptData(content_copy);

        // Prepare the request header
        RequestHeader header;
        std::copy(client_id_.begin(), client_id_.end(), header.client_id.begin());
        header.version = 3;
        header.code = boost::endian::native_to_little(static_cast<uint16_t>(RequestCode::SendFile));

        // Calculate total payload size
        uint32_t total_payload_size = sizeof(uint32_t) * 3 + // content_size, orig_file_size, packet_info
            MAX_NAME_LENGTH +        // filename
            content_copy.size();     // actual file content

        header.payload_size = boost::endian::native_to_little(total_payload_size);

        // Create the file information structure
        std::vector<uint8_t> file_info(sizeof(uint32_t) * 3 + MAX_NAME_LENGTH);

        // Convert sizes to little endian
        uint32_t content_size = boost::endian::native_to_little(static_cast<uint32_t>(content_copy.size()));
        uint32_t orig_size = boost::endian::native_to_little(static_cast<uint32_t>(content_copy.size()));
        uint32_t packet_info = boost::endian::native_to_little(makePacketInfo(1, 1));

        // Copy data into file_info buffer
        std::memcpy(file_info.data(), &content_size, sizeof(uint32_t));
        std::memcpy(file_info.data() + sizeof(uint32_t), &orig_size, sizeof(uint32_t));
        std::memcpy(file_info.data() + sizeof(uint32_t) * 2, &packet_info, sizeof(uint32_t));

        // Clear filename area and copy filename using strncpy_s
        std::memset(file_info.data() + sizeof(uint32_t) * 3, 0, MAX_NAME_LENGTH);
        strncpy_s(
            reinterpret_cast<char*>(file_info.data() + sizeof(uint32_t) * 3),
            MAX_NAME_LENGTH,
            filename.c_str(),
            _TRUNCATE
        );

        // Send header
        boost::system::error_code ec;
        size_t header_bytes = boost::asio::write(socket_, boost::asio::buffer(&header, sizeof(header)), ec);
        if (ec) {
            throw std::runtime_error("Failed to send header: " + ec.message());
        }
        std::cout << "Sent header: " << header_bytes << " bytes" << std::endl;

        // Send file info
        size_t info_bytes = boost::asio::write(socket_, boost::asio::buffer(file_info), ec);
        if (ec) {
            throw std::runtime_error("Failed to send file info: " + ec.message());
        }
        std::cout << "Sent file info: " << info_bytes << " bytes" << std::endl;

        // Send encrypted content in chunks
        size_t total_sent = 0;
        const size_t chunk_size = 16384; // 16KB chunks

        while (total_sent < content_copy.size()) {
            size_t remaining = content_copy.size() - total_sent;
            size_t current_chunk_size = std::min(chunk_size, remaining);

            size_t sent = boost::asio::write(socket_,
                boost::asio::buffer(content_copy.data() + total_sent, current_chunk_size),
                ec);

            if (ec) {
                throw std::runtime_error("Failed to send file chunk: " + ec.message());
            }

            total_sent += sent;
            std::cout << "Sent chunk: " << sent << " bytes. Total: " << total_sent << "/" << content_copy.size() << std::endl;
        }

        std::cout << "File transfer completed successfully" << std::endl;

        // Wait for server response
        readResponse();

    }
    catch (const std::exception& e) {
        std::cerr << "Error in sendEncryptedFile: " << e.what() << std::endl;
        throw;
    }
}

uint32_t Client::calculateCRC(const std::vector<uint8_t>& data) {
    uint32_t crc = 0;
    uint32_t length = data.size();

    // Process each byte
    for (uint8_t byte : data) {
        crc = (crc << 8) ^ byte;
        for (int i = 0; i < 8; ++i) {
            if (crc & 0x80000000) {
                crc = (crc << 1) ^ 0x04C11DB7;
            }
            else {
                crc = (crc << 1);
            }
        }
    }

    // Process length bytes
    for (int i = 0; i < 32; i++) {
        if ((crc ^ (length << i)) & 0x80000000) {
            crc = (crc << 1) ^ 0x04C11DB7;
        }
        else {
            crc = (crc << 1);
        }
    }

    return ~crc;
}

// Processes server's file reception confirmation:
// 1. Verifies CRC checksum
// 2. Retries on mismatch (up to 3 times)
// 3. Confirms successful transfer
void Client::handleFileReceivedResponse() {
    auto self(shared_from_this());
    std::cout << "Handling file received response..." << std::endl;

    try {
        if (last_sent_content_.empty()) {
            std::cerr << "No file content available for CRC verification" << std::endl;
            closeConnection();
            return;
        }

        uint32_t client_crc = calculateCRC(last_sent_content_);
        std::cout << "Calculated client CRC on original file content: " << client_crc << std::endl;

        // Read the server's CRC value
        uint32_t server_crc = 0;
        boost::system::error_code ec;
        size_t bytes_read = boost::asio::read(
            socket_,
            boost::asio::buffer(&server_crc, sizeof(server_crc)),
            ec
        );

        if (ec) {
            std::cerr << "Error reading server CRC: " << ec.message() << std::endl;
            closeConnection();
            return;
        }

        // Convert from network byte order
        server_crc = boost::endian::little_to_native(server_crc);
        std::cout << "Received server CRC (from decrypted data): " << server_crc << std::endl;

        if (client_crc == server_crc) {
            std::cout << "CRC verification successful!" << std::endl;
            last_sent_content_.clear();  // Clear the stored content
            sendCRCResponse(true);
            // Wait for server acknowledgment
            readResponse();
        }
        else {
            std::cout << "CRC mismatch! Server: 0x" << std::hex << server_crc
                << ", Client: 0x" << client_crc << std::dec << std::endl;

            if (retry_count_ < MAX_RETRIES) {
                retry_count_++;
                std::cout << "\nRetrying file transfer (attempt " << retry_count_
                    << "/" << MAX_RETRIES << ")" << std::endl;
                sendCRCResponse(false);

                // Small delay before retry to ensure server is ready
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                sendFile();
            }
            else {
                std::cout << "\nMaximum retry attempts (" << MAX_RETRIES
                    << ") reached. Sending final fail." << std::endl;
                last_sent_content_.clear();  // Clear the stored content
                sendCRCFinalFail();
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error in handleFileReceivedResponse: " << e.what() << std::endl;
        last_sent_content_.clear();  // Clear the stored content on error
        closeConnection();
    }
    catch (...) {
        std::cerr << "Unknown error in handleFileReceivedResponse" << std::endl;
        last_sent_content_.clear();  // Clear the stored content on error
        closeConnection();
    }
}

// Sends CRC verification response:
// 1. Constructs appropriate response (OK/Fail)
// 2. Includes client ID and version
// 3. Sends to server
// 4. Handles transmission errors
void Client::sendCRCResponse(bool success) {
    RequestHeader request;
    std::copy(client_id_.begin(), client_id_.end(), request.client_id.begin());
    request.version = 3;
    request.code = boost::endian::native_to_little(
        static_cast<uint16_t>(success ? RequestCode::CRCOk : RequestCode::CRCFail));
    request.payload_size = boost::endian::native_to_little(static_cast<uint32_t>(0));

    boost::system::error_code ec;
    boost::asio::write(socket_, boost::asio::buffer(&request, sizeof(request)), ec);
    if (ec) {
        std::cerr << "Failed to send CRC response: " << ec.message() << std::endl;
        closeConnection();
    }
}

// Handles final CRC failure after max retries:
// 1. Sends failure notification to server
// 2. Cleans up resources
// 3. Closes connection
void Client::sendCRCFinalFail() {
    RequestHeader request;
    std::copy(client_id_.begin(), client_id_.end(), request.client_id.begin());
    request.version = 3;
    request.code = boost::endian::native_to_little(static_cast<uint16_t>(RequestCode::CRCFinalFail));
    request.payload_size = boost::endian::native_to_little(static_cast<uint32_t>(0));

    boost::system::error_code ec;
    boost::asio::write(socket_, boost::asio::buffer(&request, sizeof(request)), ec);
    if (ec) {
        std::cerr << "Failed to send CRC final fail: " << ec.message() << std::endl;
    }
    closeConnection();
}

// Intended for corruption testing purposes:
// 1. Uses hardware random device
// 2. Creates proper seed sequence
// 3. Sets up MT19937 generator
void Client::initializeRNG() {
    std::random_device rd;
    std::seed_seq seq{ rd(), rd(), rd(), rd() };
    rng_.seed(seq);
}

// Enables deliberate corruption of encrypted data
// Used for testing CRC and retry mechanisms
void Client::enableRandomCorruption(size_t num_bytes) {
    random_corruption_enabled_ = true;
    max_corruption_bytes_ = std::min(num_bytes, MAX_CORRUPTION_BYTES);
    corrupted_positions_.clear();
    corrupted_positions_.reserve(max_corruption_bytes_);
    initializeRNG();
    std::cout << "Random corruption enabled. Max bytes to corrupt: " << max_corruption_bytes_ << std::endl;
}

// Disables random corruption of encrypted data testing:
// Disables test corruption mode :
// 1. Clears corruption flags
// 2. Resets corrupted positions
// 3. Returns to normal operation
void Client::disableRandomCorruption() {
    random_corruption_enabled_ = false;
    corrupted_positions_.clear();
    std::cout << "Random corruption disabled" << std::endl;
}

// Corrupts random blocks in encrypted data
// Ensures corruption of complete AES blocks
void Client::corruptData(std::vector<uint8_t>& data) {
    if (!random_corruption_enabled_ || data.empty()) {
        return;
    }

    // AES block size is 16 bytes - ensure we corrupt entire blocks
    const size_t BLOCK_SIZE = 16;
    std::uniform_int_distribution<size_t> block_dist(0, (data.size() / BLOCK_SIZE) - 1);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);

    // Determine how many blocks to corrupt (1 to max_corruption_bytes_)
    std::uniform_int_distribution<size_t> count_dist(1, max_corruption_bytes_);
    size_t num_blocks = count_dist(rng_);

    std::cout << "TEST MODE: Corrupting " << num_blocks << " blocks of encrypted data..." << std::endl;

    corrupted_positions_.clear();
    for (size_t i = 0; i < num_blocks; ++i) {
        // Corrupt an entire block
        size_t block_num = block_dist(rng_);
        size_t block_start = block_num * BLOCK_SIZE;

        // Ensure we don't corrupt the same block twice
        while (std::find(corrupted_positions_.begin(), corrupted_positions_.end(), block_start) != corrupted_positions_.end()) {
            block_num = block_dist(rng_);
            block_start = block_num * BLOCK_SIZE;
        }

        corrupted_positions_.push_back(block_start);

        // Corrupt the entire block
        for (size_t j = 0; j < BLOCK_SIZE && (block_start + j) < data.size(); ++j) {
            uint8_t original = data[block_start + j];
            uint8_t corrupted;
            do {
                corrupted = static_cast<uint8_t>(byte_dist(rng_));
            } while (corrupted == original);

            data[block_start + j] = corrupted;
            std::cout << "Corrupted byte at position " << (block_start + j)
                << " (block " << block_num << "): 0x" << std::hex
                << static_cast<int>(original) << " -> 0x"
                << static_cast<int>(corrupted) << std::dec << std::endl;
        }
    }
}
