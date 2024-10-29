import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import base64

# Generate RSA key pair
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

server_host = "localhost"
server_port = 1234  

# Create the server socket
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind((server_host, server_port))
serversocket.listen(1)
print(f"Server started at {server_host}:{server_port}, waiting for connection...")

# Accept a connection from a client
client_socket, client_address = serversocket.accept()
print(f"Connection with the address {client_address} established")

# Send the public key to the client
public_key_pem = public_key.export_key()
client_socket.send(public_key_pem)

# Receive the encrypted symmetric key from the client
encrypted_sym_key = client_socket.recv(4096)
cipher_rsa = PKCS1_OAEP.new(private_key)    #create a new cipher
sym_key = cipher_rsa.decrypt(encrypted_sym_key)

print(f"Symmetric key received: {sym_key.decode('utf-8')}")

# Now the communication is encrypted with AES
def aes_encrypt(message, sym_key):
    cipher_aes = AES.new(sym_key, AES.MODE_CBC)
    encrypted_message = cipher_aes.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher_aes.iv + encrypted_message).decode('utf-8')

def aes_decrypt(encrypted_message, sym_key):
    decoded_message = base64.b64decode(encrypted_message)
    iv = decoded_message[:16]    #initiation vector 
    encrypted_message = decoded_message[16:]   #ecrypted message
    cipher_aes = AES.new(sym_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)
    return decrypted_message.decode('utf-8')

# Communication loop 
while True:
    encrypted_message = client_socket.recv(4096).decode('utf-8')
    if not encrypted_message:
        break
    message = aes_decrypt(encrypted_message, sym_key)
    print(f"Client: {message}")
    
    response = input("Server: ")
    encrypted_response = aes_encrypt(response, sym_key)
    client_socket.send(encrypted_response.encode('utf-8'))

client_socket.close()
print("Client closed.")
