# 🔐 Cryptography Utility

A modular Java-based cryptography system implementing secure **RSA-OAEP** for asymmetric encryption/decryption and **AES-GCM** for symmetric encryption/decryption.

## 📁 Project Modules

```
cryptography/
│
├── encryption/      → Contains AES and RSA encryption utilities
├── decryption/      → Contains AES and RSA decryption utilities
└── client/          → Client module to be consumed for using encryption/decryption functionalities
```

Each module has its own source code under `src/main/java`.

---

# 🔑 Features

### - RSA Encryption (Asymmetric)
- RSA **2048-bit keypair**
- **RSA-OAEP with SHA-256 and MGF1** (`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`)
- Private/Public key extraction from PKCS12 keystore
- Safe Base64 encoding for transport

### - AES Encryption (Symmetric)
- **AES-256 GCM** mode (`AES/GCM/NoPadding`)
- 12-byte IV (nonce) generation
- 128-bit authentication tag
- AAD (Additional Authenticated Data) support
- IV + Ciphertext + Tag packaging 
- Safe Base64 encoding for transport


### - Key Storage (PKCS12) 
- Current implementation only supports key storage in KeyStore
- Private key stored in **{keystore}.p12**
- Public key extracted from certificate
- The consumer can directly pass Keystore password, or it can be read from **environment variable**
    - Example: `export KEYSTORE_PASSWORD=mysecurepassword`

---

# 🚀 Getting Started

## 1. Clone the repository
```
git clone https://github.com/ankit219302-git/cryptography
cd cryptography
```

## 2. Build the project
```
mvn clean install
```

## 3. Set the keystore password
```
export KEYSTORE_PASSWORD=yourpassword
```

---

# 🔑 Keystore Setup

The project depends on a **PKCS#12 keystore (`keystore.p12`)** which the consumer needs to provide. This keystore should contain:
- RSA private key
- X.509 certificate (contains the public key)

**For reference -**

To create the keystore from private key and certificate pem:
```
openssl pkcs12 -export
   -inkey private-key.pem
   -in x509-cert.pem
   -name alias-name
   -out keystore.p12
```

To create a x509 certificate (containing public key) from private key pem with certificate name as **test-cert** with a validity of **365 days**:
```
openssl req -new -x509
  -key private-key.pem
  -out x509-cert.pem
  -days 365
  -subj "/CN=test-cert"
```

To view the keystore:
```
keytool -list -v -keystore keystore.p12 -storetype PKCS12
```

To extract the public key:
```
openssl pkcs12 -in keystore.p12 -nokeys -out certificate.pem
openssl x509 -in certificate.pem -pubkey -noout > public_key.pem
```

---

# 🔧 How It Works

## 🔸 RSA-OAEP (Asymmetric)
Used for **encrypting/decrypting only the small payloads**, not large data.

Java transformation used:
```
RSA/ECB/OAEPWithSHA-256AndMGF1Padding
```

Encoded as Base64 for safe transmission.

## 🔸 AES-GCM (Symmetric)
Used for encrypting/decrypting larger data.

Java transformation used:
```
AES/GCM/NoPadding
```

AES payload format:
```
[IV (12 bytes)] [Ciphertext + 128-bit Tag]
```

Encoded as Base64 for safe transmission.

## 🔸 Usage (How to consume this utility)

This utility's usage is depicted in tests under the **client** module.  
The tests in `src/test/java` in client module act as a code reference on how to consume this utility in an application, once imported as a dependency.

---

# 🧪 Running Tests
The client module includes JUnit tests under `src/test/java`. To run:

```
mvn test
```

---

# 🛡 Security Notes

- **Do not commit your keystore** (used in user app - consumer) to version control.
- Set the keystore password using **environment variables** or in a safe storage.
- AES-GCM IVs are never reused with the same key.
- Use RSA only for **small secrets**, not bulk data.
- Use AES-GCM for full payload encryption with integrity protection.

---
