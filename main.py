import socket
import threading
import os
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import (
    CertificateBuilder, Name, NameAttribute, random_serial_number
)
from cryptography.x509.oid import NameOID

# Центр Сертифікації (CA)
def create_ca():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "My CA"),
        NameAttribute(NameOID.COMMON_NAME, "my-ca.example.com"),
    ])

    certificate = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    return private_key, certificate

def create_certificate(ca_private_key, ca_certificate, common_name):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    subject = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "Client/Server"),
        NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    certificate = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(ca_private_key, hashes.SHA256())
    )

    return private_key, certificate

# ECDHE: Обмін ключами
def ecdhe_key_exchange():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

# AES-GCM шифрування
def encrypt_message(key, plaintext):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

def decrypt_message(key, nonce, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Серверна логіка
def server_program():
    ca_private_key, ca_certificate = create_ca()
    server_private_key, server_certificate = create_certificate(ca_private_key, ca_certificate, "server")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 65432))
    server_socket.listen(1)
    print("[Server] Waiting for connection...")

    conn, addr = server_socket.accept()
    print(f"[Server] Connection established with {addr}")

    client_public_key = serialization.load_pem_public_key(conn.recv(1024))

    server_private_key_eph, server_public_key_eph = ecdhe_key_exchange()
    conn.send(server_public_key_eph.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    shared_secret = compute_shared_secret(server_private_key_eph, client_public_key)
    key = shared_secret[:16]

    nonce, ciphertext, tag = encrypt_message(key, b"Hello from server!")
    conn.send(nonce + tag + ciphertext)
    conn.close()

# Клієнтська логіка
def client_program():
    ca_private_key, ca_certificate = create_ca()
    client_private_key, client_certificate = create_certificate(ca_private_key, ca_certificate, "client")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 65432))

    client_private_key_eph, client_public_key_eph = ecdhe_key_exchange()
    client_socket.send(client_public_key_eph.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    server_public_key = serialization.load_pem_public_key(client_socket.recv(1024))

    shared_secret = compute_shared_secret(client_private_key_eph, server_public_key)
    key = shared_secret[:16]

    data = client_socket.recv(1024)
    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    plaintext = decrypt_message(key, nonce, ciphertext, tag)
    print(f"[Client] Decrypted message: {plaintext.decode()}")
    client_socket.close()

# Запуск клієнта і сервера
if __name__ == "__main__":
    server_thread = threading.Thread(target=server_program)
    server_thread.start()

    client_thread = threading.Thread(target=client_program)
    client_thread.start()

    server_thread.join()
    client_thread.join()
