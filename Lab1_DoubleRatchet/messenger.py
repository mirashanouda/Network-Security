import os
import pickle
import string
import json
from cryptography.hazmat.primitives.asymmetric import ec, x25519, utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

def generate_DH():
    # Generate a Diffie-Hellman key pair
    return x25519.X25519PrivateKey.generate()

def DH(dh_pair, dh_pub):
    # Returns the output from the Diffie-Hellman calculation between the private key from the DH key pair dh_pair and 
    # the DH public key dh_pub. If the DH function rejects invalid public keys, then this function may raise an exception.
    try:
        return dh_pair.exchange(dh_pub)
    except: 
        print ("Invalid public key")
        raise


def KDF_RK(rk, dh_out):
    # params: root key, DH output from previous function
    # Returns a pair (root key, chain key) as the output of applying a KDF keyed by a 
    # root key rk to a Diffie-Hellman output dh_out.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # Output length in bytes
        salt=rk,  # Using rk as the salt
        info=None,  # Empty
    )
    out_key = hkdf.derive(dh_out)
    root_key = out_key[:32]
    chain_key = out_key[32:64]
    return root_key, chain_key

    
def KDF_CK(ck):
    # params: chain key
    # Returns a pair (chain key, message key) as the output of applying a KDF keyed by a 32-byte chain key ck to some constant.
    # For generating the message key
    hmac_mk = HMAC(ck, hashes.SHA256())
    hmac_mk.update(b'\x55')
    message_key = hmac_mk.finalize()

    # Resetting HMAC for the next chain key
    hmac_ck = HMAC(ck, hashes.SHA256())
    hmac_ck.update(b'\x66')
    next_chain_key = hmac_ck.finalize()

    return message_key, next_chain_key


def encrypt(mk, plaintext, associated_data):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=b'\x00' * 32, # zero-filled byte sequence equal to the hash's output length
        info=None,
    )
    hkdf_out = hkdf.derive(mk)
    encryption_key = hkdf_out[:32]
    authentication_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
 
    # Compute HMAC
    hmac = HMAC(authentication_key, hashes.SHA256())
    hmac.update(associated_data + ciphertext)
    hmac_digest = hmac.finalize()

    # Return ciphertext appended with HMAC digest
    return ciphertext + hmac_digest

def decrypt(mk, ciphertext, associated_data):
    # Returns the AEAD decryption of ciphertext with message key mk. If authentication fails, an exception will be raised that terminates processing.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=b'\x00' * 32, # zero-filled byte sequence equal to the hash's output length
        info=None,
    )
    hkdf_out = hkdf.derive(mk)
    encryption_key = hkdf_out[:32]
    authentication_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    # Split the ciphertext into the actual ciphertext and the HMAC digest
    ciphertext, hmac_digest = ciphertext[:-32], ciphertext[-32:]

    # Verify the HMAC
    hmac = HMAC(authentication_key, hashes.SHA256())
    hmac.update(associated_data + ciphertext)
    hmac.verify(hmac_digest)

    # Decrypt the ciphertext
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext.decode('utf-8')


class MessengerServer:
    def __init__(self, server_signing_key):
        self.server_signing_key = server_signing_key

    def signCert(self, cert):
        # Generate the signature using the server's signing private key
        return self.server_signing_key.sign(cert, ec.ECDSA(hashes.SHA256()))

class MessengerClient:

    def __init__(self, name, server_signing_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk # server's public key
        # self.client_priKey = ec.generate_private_key(ec.SECP256R1())
        self.client_priKey = generate_DH()
        self.client_pubKey = self.client_priKey.public_key()
        self.conns = {}
        self.certs = {}
        self.cks = {}
        self.last_operation = {}
 
    def generateCertificate(self):
        cert = {
            'username': self.name,
            'public_key': self.client_pubKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
        serialized_cert = json.dumps(cert).encode()
        return serialized_cert

    def receiveCertificate(self, certificate, signature):
        cert = json.loads(certificate.decode())
        try:
            self.server_signing_pk.verify(
                signature,
                certificate,  # Ensure this is the exact byte string that was signed
                ec.ECDSA(hashes.SHA256())  # Match the hash function used in signCert
            )
            # Deserialize the certificate
            self.certs[cert['username']] = cert
            return
        except:
            print("Verification failed: at ", cert['username'])
            raise

    def sendMessage(self, name, message):
        # print("connections: ", self.conns)
        if not name in self.conns:
            # print("######## New send to", name)
            self.conns[name] = load_pem_public_key(self.certs[name]['public_key'].encode())
            dh_out = DH(self.client_priKey, self.conns[name])
            # print("dh_out", dh_out)
            self.rk, self.cks[name] = KDF_RK(dh_out, dh_out)
            # print("enc rk", self.rk, "enc ck", self.cks[name])

        if name in self.conns and name in self.last_operation and self.last_operation[name] != "send":
            # print("######## New send to", name)
            self.client_priKey = generate_DH()
            self.client_pubKey = self.client_priKey.public_key()
            dh_out = DH(self.client_priKey, self.conns[name])
            self.rk, self.cks[name] = KDF_RK(dh_out, dh_out)

        self.last_operation[name] = "send"
        # print("send ck for ", name , " ", self.cks[name])
        mk, self.cks[name] = KDF_CK(self.cks[name])
        # print("send next ck for ", name , " ", self.cks[name])
        self.client_pubKey = self.client_priKey.public_key()
        header = self.client_pubKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # print("enc mk", mk, " enc ck", self.cks[name])
        encrypted_msg = encrypt(mk, message, header)
        # print("header = ", header)
        return header, encrypted_msg

    def receiveMessage(self, name, header, ciphertext): 
        if not name in self.conns or load_pem_public_key(header) != self.conns[name]:
            # print("######## New rec from", name)
            self.conns[name] = load_pem_public_key(header)
            dh_out = DH(self.client_priKey, self.conns[name])
            self.rk, self.cks[name] = KDF_RK(dh_out, dh_out)
        
        self.last_operation[name] = "rec"
        # print("rec ck for ", name , " ", self.cks[name])
        mk, self.cks[name] = KDF_CK(self.cks[name])
        # print("rec next ck for ", name , " ", self.cks[name])
        # print("dec mk", mk, " dec ck", self.cks[name])
        try:
            return decrypt(mk, ciphertext, header)
        except:
            return None
    
