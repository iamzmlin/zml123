#!/usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
import binascii as ba
import socketserver
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes

def encrypt_file(key, iv, file_path, output_path):
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), default_backend())
    encryptor = cipher.encryptor()
    with open(file_path, 'rb') as f:
        file_data = f.read()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(key, iv, file_path, output_path):
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), default_backend())
    decryptor = cipher.decryptor()
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

def encrypt_message(key, iv, message):
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return encrypted_message

def decrypt_message(key, iv, encrypted_message):
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message

def gen_hmac(key, message):
    hmac = HMAC(key, hashes.SHA256())
    hmac.update(message)
    return hmac.finalize()

def v_hmac(key, message, rec_hmac):
    hmac = HMAC(key, hashes.SHA256())
    hmac.update(message)
    try:
        hmac.verify(rec_hmac)
        return True
    except InvalidSignature:
        return False


def load_dh_params():
    with open('./dh_2048_params.bin', 'rb') as f:
        params = load_der_parameters(f.read(), default_backend())
    print('Parameters have been read from file, Server is ready for requests ...')
    return params


def generate_dh_prvkey(params):
    return params.generate_private_key()


def check_client_pubkey(pubkey):
    if isinstance(pubkey, dh.DHPublicKey):
        return True
    else:
        return False


class Dh_Handler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.params = load_dh_params()
        self.state = 0
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)
 
    def handle(self):
        
        self.data = self.request.recv(3072).strip()
        if self.state == 0 and self.data == b'127.0.0.1':
            self.state = 1
            print(self.data, self.state)
            response = b'Hey there!'
            self.request.sendall(response)
        else:
            response = b'Access denied, hanging up'
            self.request.sendall(response)
            return
        
        

        self.data = self.request.recv(3072).strip()
        if self.state == 1 and self.data == b'Params?':
            self.state = 2
            print(self.data, self.state)
            dh_params = self.params
            response = dh_params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
            self.request.sendall(response)
        else:
            response = b'I do not understand you, hanging up'
            self.request.sendall(response)
            return

        self.data = self.request.recv(3072).strip()
        if self.state == 2 and bytearray(self.data)[0:18] == b'Client public key:':
            client_pubkey = load_pem_public_key(bytes(bytearray(self.data)[18:]), default_backend())
            if client_pubkey:
                server_keypair = generate_dh_prvkey(self.params)
                response = b'Server public key:' + server_keypair.public_key().public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                shared_secret = server_keypair.exchange(client_pubkey)
                self.shared_secret = shared_secret
                self.state = 3
                print(self.data, self.state)
                self.request.sendall(response)
                print('Shared Secret:\n{}'.format(ba.hexlify(shared_secret)))
            else:
                response = b'Invalid client public key, hanging up'
                self.request.sendall(response)
                return  

        # Handle state 3
        self.data = self.request.recv(3072).strip()
        if self.state == 3 and self.data == b'Please give me the salt':
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=48,
                salt=None,
                info=b'Handshake data',
                backend=default_backend()
            )

            key_material = kdf.derive(shared_secret)
            self.key = key_material[:16]
            self.mac_key = key_material[16:32]
            self.salt = os.urandom(8)
            self.request.sendall(b'Server salt:' + self.salt)
            self.state = 4


        self.data = self.request.recv(3072).strip()   
        if self.state == 4 and bytearray(self.data) == b'1':
            while True:
                self.data = self.request.recv(3072).strip()
                received_message = self.data[:-32]
                rec_hmac = self.data[-32:]
                if v_hmac(self.mac_key, received_message, rec_hmac):
                    decrypted_message = decrypt_message(self.key, self.salt, received_message)
                    print('The message after decrypted: {}'.format(decrypted_message.decode()))
                    response = input('The response:')
                    encrypted_response = encrypt_message(self.key, self.salt, response.encode())
                    hmac = gen_hmac(self.mac_key, encrypted_response)
                    self.request.sendall(encrypted_response + hmac)
                else:
                    print('Message authentication failed')
                           
        elif self.state == 4 and bytearray(self.data) == b'2':
            filedata = self.request.recv(3072).strip()
            received_file = filedata[:-32]
            rec_hmac = filedata[-32:]

            if v_hmac(self.mac_key, received_file, rec_hmac):
                with open('received_file', 'wb') as f:
                    f.write(filedata)
                with open('decrypt_received_file', 'wb') as f:
                    f.write(decrypt_message(self.key, self.salt, received_file))
                print('The file is received successfully.')
                self.request.sendall(b'File received.')
            else:
                print('The file authentication is failed')
            
        
        


def main():
    host, port = '', 7777 
    dh_server = socketserver.TCPServer((host, port), Dh_Handler)
    try:
        dh_server.serve_forever()
    except KeyboardInterrupt:
        dh_server.shutdown()
        sys.exit(0)


if __name__ == '__main__':
    main()
