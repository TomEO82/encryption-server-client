// Client.h - Main client class declaration with cryptographic and network functionality.
// Tomer Rosenfeld 314626425
#pragma once

#include <string>
#include <vector>
#include <random>
#include <boost/asio.hpp>
#include <memory>
#include "Protocol.h"
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/oaep.h>

#pragma pack(push, 1)
struct RawResponseHeader {
    uint8_t version;
    uint16_t code;
    uint32_t payload_size;
};
#pragma pack(pop)

class Client : public std::enable_shared_from_this<Client> {
public:
    Client(boost::asio::io_context& io_context, const std::string& server_ip, int server_port);

    void start(); //  Initializes client and loads/generates necessary keys
    void initiateConnection(); // Begins server connection process
    void enableRandomCorruption(size_t num_bytes = MAX_CORRUPTION_BYTES);
    void disableRandomCorruption();

private:
    bool random_corruption_enabled_ = false;
    void connect();
    void sendMessage(const std::string& message);
    void readResponse();
    void sendRegistrationRequest();
    void sendReconnectionRequest();  
    void handleRegistrationResponse();
    void handleReconnectionResponse(); 
    void storeClientInfo();
    bool loadClientInfo();
    std::string clientIdToString() const;
    bool readTransferInfo();
    void corruptData(std::vector<uint8_t>& data);
    void initializeRNG();

    // RSA key handling methods
    void generateRSAKeys();
    bool loadRSAKeys();
    void storePrivateKey();
    void sendPublicKey();
    void readPublicKeyResponse();
    void closeConnection();

    // AES key handling
    bool decryptAESKey(const std::vector<uint8_t>& encrypted_key);

    // File operations
    void storePrivateKeyToFile(const std::string& filename);
    bool loadPrivateKeyFromFile(const std::string& filename);
	void loadPrivateKey();
    void storePrivateKeyToFile(std::ofstream& file);

    // Member variables
    boost::asio::io_context& io_context_; //  Boost ASIO IO context for async operations
    boost::asio::ip::tcp::socket socket_; // TCP socket for server communication
    std::string server_ip_;
    int server_port_;
    boost::asio::streambuf response_;
    std::array<uint8_t, CLIENT_ID_SIZE> client_id_; // Unique client identifier
    std::string client_name_;
    bool is_registered_;
    std::string file_path_;

    CryptoPP::RSA::PrivateKey private_key_; //  RSA private key for encryption
    CryptoPP::RSA::PublicKey public_key_; //  RSA public key for server
    bool keys_generated_;

    std::vector<uint8_t> aes_key_; // Symmetric key for file encryption
    bool aes_key_received_;

    RawResponseHeader response_header_;

    std::mt19937 rng_;
    std::vector<size_t> corrupted_positions_;
    size_t max_corruption_bytes_;
    std::vector<uint8_t> last_sent_content_;  // To store the last sent file content

    // File transfer methods
    void sendFile(); // Handles file encryption and transmission
    std::vector<uint8_t> encryptFileContent(const std::vector<uint8_t>& file_content);
    std::vector<uint8_t> readFileContent(const std::string& filepath);
    void sendEncryptedFile(const std::string& filename, const std::vector<uint8_t>& encrypted_content);

    // Additional member variables for file transfer
    size_t retry_count_ = 0;
    static const size_t MAX_RETRIES = 3;
    static const size_t MAX_PACKET_SIZE = 16384; // 16KB chunks

    // CRC-related methods
    uint32_t calculateCRC(const std::vector<uint8_t>& data); // Computes checksum for file verification
    void handleFileReceivedResponse(); // Processes server's file reception confirmation
    void sendCRCResponse(bool success);
    void sendCRCFinalFail();
};