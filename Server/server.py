import socket
import threading
import struct
import uuid
import base64
import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Global constants
DEFAULT_IP = '127.0.0.1'
DEFAULT_PORT = 1256
CLIENT_ID_SIZE = 16
MAX_NAME_LENGTH = 255
CLIENT_FILES_DIR = "client_files"

# Request codes
REQUEST_REGISTER = 825
REQUEST_SEND_PUBLIC_KEY = 826
REQUEST_RECONNECT = 827
REQUEST_SEND_FILE = 828
REQUEST_CRC_OK = 900
REQUEST_CRC_FAIL = 901
REQUEST_CRC_FINAL_FAIL = 902

# Response codes
RESPONSE_REGISTER_SUCCESS = 1600
RESPONSE_REGISTER_FAIL = 1601
RESPONSE_PUBLIC_KEY_RECEIVED = 1602
RESPONSE_FILE_RECEIVED = 1603
RESPONSE_MESSAGE_RECEIVED = 1604
RESPONSE_RECONNECT_APPROVED = 1605
RESPONSE_RECONNECT_DENIED = 1606
RESPONSE_GENERAL_ERROR = 1607

# Structures
REQUEST_HEADER_FORMAT = f"<{CLIENT_ID_SIZE}sBHI"
RESPONSE_HEADER_FORMAT = "<BHI"

# Represents connected client
# Stores name, ID, keys, and connection state
class Client:
    def __init__(self, name, client_id):
        self.name = name
        self.client_id = client_id
        self.public_key = None
        self.aes_key = None

clients = {}  # Dictionary to store registered clients

# Initializes server storage:
# 1. Creates client_files directory if missing
# 2. Sets up appropriate permissions
# 3. Handles creation errors
def setup_client_files_directory():
    """Create directory for client files if it doesn't exist."""
    try:
        if not os.path.exists(CLIENT_FILES_DIR):
            os.makedirs(CLIENT_FILES_DIR)
            print(f"Created directory '{CLIENT_FILES_DIR}' for client files")
        else:
            print(f"Directory '{CLIENT_FILES_DIR}' already exists")
    except Exception as e:
        print(f"Error creating client files directory: {e}")
        raise

# Generates 256-bit AES key for file encryption
def generate_aes_key():
    """Generate a new 256-bit AES key."""
    try:
        key = get_random_bytes(32)  # 32 bytes = 256 bits
        print(f"Generated AES key of size: {len(key)} bytes")
        return key
    except Exception as e:
        print(f"Error generating AES key: {str(e)}")
        raise

# Encrypts AES key with client's public RSA key
def encrypt_aes_key(aes_key, public_key_data):
    """Encrypt the AES key using the client's public RSA key."""
    try:
        print("Starting AES key encryption...")
        # Convert the public key string to RSA key object
        public_key = RSA.import_key(public_key_data)
        print("Successfully imported public key")
        
        # Create PKCS1_OAEP cipher
        cipher = PKCS1_OAEP.new(public_key)
        print("Created PKCS1_OAEP cipher")
        
        # Encrypt the AES key
        encrypted_aes_key = cipher.encrypt(aes_key)
        print("Successfully encrypted AES key")
        
        return encrypted_aes_key
    except Exception as e:
        print(f"Error in encrypt_aes_key: {str(e)}")
        return None

# Manages client reconnection:
# 1. Verifies client identity
# 2. Generates new AES key
# 3. Reestablishes secure connection
def handle_reconnection(client_socket, client_address, client_id, name):
    """Handle client reconnection request."""
    print(f"Handling reconnection request from {client_address}")
    try:
        # Set TCP_NODELAY
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Convert client_id to string for comparison
        client_id_str = ''.join(format(b, '02x') for b in client_id)
        
        for cid, client in clients.items():
            cid_str = ''.join(format(b, '02x') for b in cid)
            if cid_str == client_id_str and client.name == name:
                print(f"Valid reconnection for client: {name}")
                
                # Generate and encrypt new AES key
                aes_key = get_random_bytes(32)
                print(f"Generated new AES key for reconnected client")
                
                encrypted_aes_key = encrypt_aes_key(aes_key, client.public_key)
                if encrypted_aes_key is None:
                    raise Exception("Failed to encrypt AES key")
                
                # Store the new key
                client.aes_key = aes_key
                
                # Prepare response data
                response = bytearray([
                    3,      # version
                    0x45,   # code (1605) low byte
                    0x06,   # code (1605) high byte
                    0x80,   # size (128) low byte
                    0x00,   # size byte 2
                    0x00,   # size byte 3
                    0x00    # size byte 4
                ])
                
                print("Sending header bytes:", ' '.join(format(b, '02X') for b in response))
                
                # Send version byte
                client_socket.send(bytes([response[0]]))
                # Send code bytes
                client_socket.send(bytes(response[1:3]))
                # Send size bytes
                client_socket.send(bytes(response[3:7]))
                
                print("Header sent successfully")
                
                # Small delay to ensure header is processed
                time.sleep(0.1)
                
                # Send encrypted key
                client_socket.sendall(encrypted_aes_key)
                print(f"Sent encrypted AES key ({len(encrypted_aes_key)} bytes)")
                
                return True
                
        print(f"No matching client found for {name}")
        return False
        
    except Exception as e:
        print(f"Error in handle_reconnection: {str(e)}")
        return False
    
def generate_client_id():
    return uuid.uuid4().bytes

def read_port():
    try:
        with open("port.info", "r") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        print(f"port.info not found. Using default port {DEFAULT_PORT}.")
        return DEFAULT_PORT
    except ValueError:
        print(f"Invalid port in port.info. Using default port {DEFAULT_PORT}.")
        return DEFAULT_PORT

def handle_registration(client_socket, client_address, name):
    client_id = generate_client_id()
    
    if name in [client.name for client in clients.values()]:
        # Name already exists
        response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_REGISTER_FAIL, 0)
        client_socket.send(response_header)
        print(f"Registration failed for {name} from {client_address}. Name already exists.")
    else:
        # Registration successful
        clients[client_id] = Client(name, client_id)
        response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_REGISTER_SUCCESS, CLIENT_ID_SIZE)
        client_socket.send(response_header + client_id)
        print(f"Registered new client: {name} from {client_address}")

# Manages public key exchange:
# 1. Receives client's public key
# 2. Stores key with client data
# 3. Generates new AES key
# 4. Encrypts and sends AES key
# 5. Handles encryption errors
def handle_public_key(client_socket, client_address, client_id, payload_size):
    """Handle receiving public key and sending back encrypted AES key."""
    try:
        print(f"\nHandling public key from client at {client_address}")
        # Receive the public key
        public_key_data = client_socket.recv(payload_size)
        print(f"Received public key data of size: {len(public_key_data)} bytes")
        
        if client_id in clients:
            # Store the public key
            clients[client_id].public_key = public_key_data
            print(f"Stored public key for client: {clients[client_id].name}")

            # Generate new AES key for this client
            aes_key = generate_aes_key()
            clients[client_id].aes_key = aes_key
            print(f"Generated new AES key of size: {len(aes_key)} bytes")

            # Encrypt the AES key with client's public key
            encrypted_aes_key = encrypt_aes_key(aes_key, public_key_data)
            if encrypted_aes_key is None:
                raise Exception("Failed to encrypt AES key")
            
            print(f"Successfully encrypted AES key. Encrypted size: {len(encrypted_aes_key)} bytes")

            # Send response to client
            response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_PUBLIC_KEY_RECEIVED, len(encrypted_aes_key))
            client_socket.send(response_header + encrypted_aes_key)
            print(f"Sent encrypted AES key to client: {clients[client_id].name}")

        else:
            print(f"Error: Unknown client ID: {client_id.hex()}")
            # Send error response
            response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_GENERAL_ERROR, 0)
            client_socket.send(response_header)

    except Exception as e:
        print(f"Error in handle_public_key: {str(e)}")
        # Send error response
        try:
            response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_GENERAL_ERROR, 0)
            client_socket.send(response_header)
        except Exception as send_error:
            print(f"Error sending error response: {str(send_error)}")

# Implements Linux-compatible CRC32:
# 1. Processes data byte by byte
# 2. Includes file length in calculation
# 3. Matches cksum command output
# 4. Returns 32-bit checksum
def calculate_crc(data):
    """Calculate CRC32 checksum compatible with Linux cksum command."""
    crc = 0
    length = len(data)
    
    # Process each byte
    for byte in data:
        crc = ((crc << 8) | byte) & 0xFFFFFFFF
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) & 0xFFFFFFFF) ^ 0x04C11DB7
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    
    # Process length bytes
    for i in range(32):
        if (crc ^ (length << i)) & 0x80000000:
            crc = ((crc << 1) & 0xFFFFFFFF) ^ 0x04C11DB7
        else:
            crc = (crc << 1) & 0xFFFFFFFF
    
    return ~crc & 0xFFFFFFFF            

# Manages file reception:
# 1. Receives encrypted file data
# 2. Decrypts using stored AES key
# 3. Verifies CRC
# 4. Stores file on success
def handle_file_transfer(client_socket, client_address, client_id, payload_size):
    """Handle receiving encrypted file from client."""
    try:
        print(f"\nHandling file transfer from client at {client_address}")
        
        # First, receive the file transfer request structure (fixed size header)
        file_header_size = 4 + 4 + 4 + MAX_NAME_LENGTH  # content_size + orig_file_size + packet_info + filename
        file_header_data = client_socket.recv(file_header_size)
        
        if len(file_header_data) < 12:  # Basic size check for the numeric fields
            raise ValueError("Incomplete file header received")
            
        # Unpack the fixed-size numeric fields
        content_size, orig_file_size, packet_info = struct.unpack("<III", file_header_data[:12])
        
        # Extract filename - handle as bytes and decode only the filename portion
        filename_bytes = file_header_data[12:12+MAX_NAME_LENGTH]
        # Find the null terminator in the filename
        null_pos = filename_bytes.find(b'\0')
        if null_pos != -1:
            filename = filename_bytes[:null_pos].decode('utf-8')
        else:
            filename = filename_bytes.decode('utf-8').rstrip()
        
        print(f"File transfer details:")
        print(f"Content size: {content_size}")
        print(f"Original size: {orig_file_size}")
        print(f"Filename: {filename}")
        
        # Now receive the encrypted file content
        encrypted_data = bytearray()
        remaining = content_size
        
        while remaining > 0:
            chunk_size = min(16384, remaining)  # 16KB chunks
            chunk = client_socket.recv(chunk_size)
            if not chunk:
                raise ConnectionError("Connection closed while receiving file data")
            encrypted_data.extend(chunk)
            remaining -= len(chunk)
            print(f"Received chunk of {len(chunk)} bytes, {remaining} bytes remaining")
        
        print(f"Received complete encrypted file data: {len(encrypted_data)} bytes")

        if client_id in clients:
            client = clients[client_id]
            
            # First decrypt the data
            decrypted_data = decrypt_file(encrypted_data, client.aes_key)
            if not decrypted_data:
                print("Decryption failed or corruption detected")
                # Send a CRC that will definitely cause a mismatch
                response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_FILE_RECEIVED, 4)
                crc_bytes = struct.pack("<I", 0xFFFFFFFF)  # Send max value to force mismatch
                client_socket.sendall(response_header + crc_bytes)
                print("Sent invalid CRC to trigger retry")
                return False
            
            # Calculate CRC on decrypted data
            crc = calculate_crc(decrypted_data)
            print(f"Calculated CRC on decrypted data: {crc}")
            
            # Send CRC to client for verification
            response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_FILE_RECEIVED, 4)
            crc_bytes = struct.pack("<I", crc)
            client_socket.sendall(response_header + crc_bytes)
            print("Sent CRC to client, waiting for verification response...")
            
            # Wait for client's verification response
            header_data = client_socket.recv(struct.calcsize(REQUEST_HEADER_FORMAT))
            if header_data:
                client_id, version, code, payload_size = struct.unpack(REQUEST_HEADER_FORMAT, header_data)
                
                if code == REQUEST_CRC_OK:
                    print("Client confirmed CRC ok, storing file...")
                    # Only store file after CRC is confirmed
                    if store_client_file(client.name, filename, encrypted_data, decrypted_data):
                        print("File stored successfully")
                        response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_MESSAGE_RECEIVED, 0)
                        client_socket.send(response_header)
                        return True
                    else:
                        print("Failed to store file")
                        return False
                elif code == REQUEST_CRC_FAIL:
                    print("Client reported CRC mismatch, discarding received file")
                    response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_MESSAGE_RECEIVED, 0)
                    client_socket.send(response_header)
                    return False
                elif code == REQUEST_CRC_FINAL_FAIL:
                    print("Client reported final CRC failure, aborting transfer")
                    response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_MESSAGE_RECEIVED, 0)
                    client_socket.send(response_header)
                    return False
            
            print("No valid response received from client")
            return False

        else:
            raise ValueError(f"Unknown client ID: {client_id.hex()}")

    except Exception as e:
        print(f"Error handling file transfer: {str(e)}")
        try:
            # Send error response
            response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_GENERAL_ERROR, 0)
            client_socket.send(response_header)
        except Exception as send_error:
            print(f"Error sending error response: {str(send_error)}")
        return False

# Main client handler:
# 1. Processes incoming requests
# 2. Routes to appropriate handlers
# 3. Maintains client connection
def handle_client(client_socket, client_address):
    print(f"Accepted connection from {client_address}")
    
    try:
        while True:
            try:
                # Receive the request header
                header_data = client_socket.recv(struct.calcsize(REQUEST_HEADER_FORMAT))
                if not header_data:
                    print(f"Client {client_address} disconnected")
                    break
                
                print(f"Raw header data: {header_data.hex()}")
                client_id, version, code, payload_size = struct.unpack(REQUEST_HEADER_FORMAT, header_data)
                
                print(f"Received request: version={version}, code={code}, payload_size={payload_size}")
                
                if code == REQUEST_REGISTER:
                    # Receive the name
                    name_data = client_socket.recv(MAX_NAME_LENGTH)
                    name = name_data.decode('utf-8').rstrip('\0')
                    handle_registration(client_socket, client_address, name)
                
                elif code == REQUEST_SEND_PUBLIC_KEY:
                    handle_public_key(client_socket, client_address, client_id, payload_size)
                
                elif code == REQUEST_CRC_OK:
                    print(f"Client {client_address} confirmed CRC ok")
                    response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_MESSAGE_RECEIVED, 0)
                    client_socket.send(response_header)
            
                elif code == REQUEST_CRC_FAIL:
                    print(f"Client {client_address} reported CRC mismatch, awaiting retry")
                    response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_MESSAGE_RECEIVED, 0)
                    client_socket.send(response_header)
                    
                elif code == REQUEST_CRC_FINAL_FAIL:
                    print(f"Client {client_address} reported final CRC failure")
                    response_header = struct.pack(RESPONSE_HEADER_FORMAT, 3, RESPONSE_MESSAGE_RECEIVED, 0)
                    client_socket.send(response_header)
                
                elif code == REQUEST_RECONNECT:
                    # Handle reconnection request
                    name_data = client_socket.recv(MAX_NAME_LENGTH)
                    name = name_data.decode('utf-8').rstrip('\0')
                    if not handle_reconnection(client_socket, client_address, client_id, name):
                        print(f"Failed reconnection attempt from {client_address}")
                        break
                
                elif code == REQUEST_SEND_FILE:
                    handle_file_transfer(client_socket, client_address, client_id, payload_size)
                
                else:
                    print(f"Received unknown request code {code} from {client_address}")
            
            except ConnectionResetError:
                print(f"Client {client_address} disconnected unexpectedly")
                break
            except ConnectionError as e:
                print(f"Connection error with client {client_address}: {str(e)}")
                break
            except Exception as e:
                print(f"Error handling client {client_address}: {str(e)}")
                print("Exception details:", str(e))
                break
    
    finally:
        print(f"Closing connection from {client_address}")
        try:
            client_socket.close()
        except:
            pass

# Creates unique filename for stored files:
# 1. Checks for existing files
# 2. Appends counter if needed
# 3. Ensures no overwrites
# 4. Returns safe filename
def generate_unique_filename(original_filename):
    """Generate a unique filename in the client files directory."""
    base, extension = os.path.splitext(original_filename)
    counter = 1
    new_filename = original_filename
    
    while os.path.exists(os.path.join(CLIENT_FILES_DIR, new_filename)):
        new_filename = f"{base}_{counter}{extension}"
        counter += 1
    
    return new_filename

# Decrypts received file using stored AES key
def decrypt_file(encrypted_data, aes_key):
    """Decrypt a file using the stored AES key."""
    try:
        # Create a zero IV (as specified in the project requirements)
        iv = b'\x00' * 16  # 16 bytes of zeros
        
        # Create AES cipher in CBC mode
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Verify the padding is valid
        padding_length = decrypted_data[-1]
        if padding_length > 16 or padding_length < 1:  # Invalid padding
            print("Invalid padding detected - possible corruption")
            return None
            
        # Verify all padding bytes are correct
        padding = decrypted_data[-padding_length:]
        if not all(x == padding_length for x in padding):
            print("Inconsistent padding detected - possible corruption")
            return None
            
        # Remove padding
        decrypted_data = decrypted_data[:-padding_length]
        
        return decrypted_data
        
    except Exception as e:
        print(f"Error decrypting file: {str(e)}")
        return None

# Safely stores received files:
# 1. Sanitizes client name and filename
# 2. Creates client-specific directory
# 3. Stores both encrypted and decrypted versions
# 4. Handles storage errors and cleanup
def store_client_file(client_name, filename, encrypted_data, decrypted_data):
    """Store a client's file in the client files directory."""
    try:
        # Sanitize the client name and filename
        safe_client_name = "".join(c for c in client_name if c.isalnum() or c in (' ', '-', '_'))
        safe_filename = "".join(c for c in filename if c.isalnum() or c in ('-', '_', '.'))
        
        # Create client directory
        client_dir = os.path.join(CLIENT_FILES_DIR, safe_client_name)
        os.makedirs(client_dir, exist_ok=True)

        decrypted_path = os.path.join(client_dir, safe_filename)
        encrypted_path = os.path.join(client_dir, f"encrypted_{safe_filename}")
        
        # Store both versions
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)

        print(f"Successfully stored file '{safe_filename}'")
        print(f"Original size: {len(decrypted_data)} bytes")
        print(f"Encrypted size: {len(encrypted_data)} bytes")
        return True
            
    except Exception as e:
        print(f"Error storing file: {str(e)}")
        # Clean up any partially written files
        try:
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
            if os.path.exists(decrypted_path):
                os.remove(decrypted_path)
        except:
            pass
        return False
    

def main():
    try:
        # Set up client files directory
        setup_client_files_directory()
        
        port = read_port()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((DEFAULT_IP, port))
        server.listen(5)
        print(f"Server listening on {DEFAULT_IP}:{port}")

        while True:
            client_sock, address = server.accept()
            client_handler = threading.Thread(
                target=handle_client,
                args=(client_sock, address)
            )
            client_handler.start()
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        if 'server' in locals():
            server.close()

if __name__ == "__main__":
    main()