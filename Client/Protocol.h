// Protocol.h - Core protocol definitions and structures for client-server communication.
// Tomer Rosenfeld 314626425
#pragma once

#include <cstdint>
#include <array>
constexpr size_t CLIENT_ID_SIZE = 16; // Size of client identifier (16 bytes)
constexpr size_t MAX_NAME_LENGTH = 255; // Size of client identifier (16 bytes)
constexpr size_t MAX_CORRUPTION_BYTES = 3; // Maximum bytes to corrupt in test mode (3 bytes)


#pragma pack(push, 1)
// Base structure for all client requests
struct RequestHeader {
    std::array<uint8_t, CLIENT_ID_SIZE> client_id; // Unique client identifier
    uint8_t version; // Protocol version
    uint16_t code; // Request type code
    uint32_t payload_size; // Size of following payload
};

struct ResponseHeader {
    uint8_t version; // Protocol version
    uint16_t code; // Response type code
    uint32_t payload_size; // Size of following payload
};

struct RegistrationRequest {
    RequestHeader header;
    char name[MAX_NAME_LENGTH];
};

struct PublicKeyRequest {
    RequestHeader header;
    // The actual key will be sent separately
};
#pragma pack(pop)

// Request codes
// Defines all possible client request types (825-902)
enum class RequestCode : uint16_t { 
    Register = 825,
    SendPublicKey = 826,
    Reconnect = 827,
    SendFile = 828,
    CRCOk = 900,
    CRCFail = 901,
    CRCFinalFail = 902
};

// Response codes
// Defines all possible server response types (1600-1607)
enum class ResponseCode : uint16_t {
    RegisterSuccess = 1600,
    RegisterFail = 1601,
    PublicKeyReceived = 1602,  // Includes encrypted AES key in payload
    FileReceived = 1603,
    MessageReceived = 1604,
    ReconnectApproved = 1605,
    ReconnectDenied = 1606,
    GeneralError = 1607
};

struct AESKeyResponse {
    ResponseHeader header;
    // The encrypted AES key will follow in the payload
};

struct FileTransferRequest {
    RequestHeader header;
    uint32_t content_size;        // Size after encryption
    uint32_t orig_file_size;      // Original file size
    uint32_t packet_info;         // First 2 bytes: current packet, Last 2 bytes: total packets
    char filename[MAX_NAME_LENGTH];
    // Message content follows (encrypted file data)
};

// Combines current and total packet numbers:
// 1. Packs two 16-bit values into 32-bit integer
// 2. Current packet in high bits
// 3. Total packets in low bits
inline uint32_t makePacketInfo(uint16_t current, uint16_t total) {
    return (static_cast<uint32_t>(current) << 16) | total;
}

// Extracts packet numbers from combined value:
// 1. Separates 32-bit value into two 16-bit numbers
// 2. Updates current and total packet references
inline void extractPacketInfo(uint32_t packet_info, uint16_t& current, uint16_t& total) {
    current = static_cast<uint16_t>(packet_info >> 16);
    total = static_cast<uint16_t>(packet_info & 0xFFFF);
}