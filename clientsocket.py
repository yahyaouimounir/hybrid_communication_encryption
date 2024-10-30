import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import base64

def start_client():
    server_host = 'localhost'
    server_port = 1234
    
    # Input symmetric key
    sym_key = input("Enter symmetric key: ").encode('utf-8')

    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))
    print(f"Connected to server at {server_host}:{server_port}")
    
    # Receive the public RSA key from the server
    public_key_pem = client_socket.recv(4096)
    public_key = RSA.import_key(public_key_pem)
    print(f"public key : {public_key_pem}")
    
    # Encrypt the symmetric key with the RSA public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_sym_key = cipher_rsa.encrypt(sym_key)  #encrypt symetric key with the cipher
    
    # Send the encrypted symmetric key to the server
    client_socket.send(encrypted_sym_key)
    
    print("Symmetric key sent to server (encrypted with RSA).")

    # Now the communication is encrypted with AES
    def aes_encrypt(message, sym_key):
        cipher_aes = AES.new(sym_key, AES.MODE_CBC)
        encrypted_message = cipher_aes.encrypt(pad(message.encode('utf-8'), AES.block_size))
        return base64.b64encode(cipher_aes.iv + encrypted_message).decode('utf-8')

    def aes_decrypt(encrypted_message, sym_key):
        decoded_message = base64.b64decode(encrypted_message)
        iv = decoded_message[:16]
        encrypted_message = decoded_message[16:]
        cipher_aes = AES.new(sym_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)
        return decrypted_message.decode('utf-8')

    # Communication loop (AES encrypted)
    while True:
        message = input("Client: ")
        encrypted_message = aes_encrypt(message, sym_key)
        client_socket.send(encrypted_message.encode('utf-8'))
        
        encrypted_response = client_socket.recv(4096).decode('utf-8')
        response = aes_decrypt(encrypted_response, sym_key)
        print(f"Server: {response}")

    client_socket.close()
    print("Client closed.")

if __name__ == "__main__":
    start_client()