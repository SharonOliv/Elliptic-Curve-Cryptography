# ECC Key Exchange and AES Encryption

This repository shows the implementation of a secure key exchange mechanism using **Elliptic Curve Cryptography (ECC)** and performs **AES-based encryption and decryption** of messages. Additionally, it compares the performance and security characteristics of two elliptic curves: `secp256r1` and `secp384r1`.

## Project Overview

- **Key Exchange**: 
  - Generate ECC key pairs.
  - Exchange public keys using serialization (PEM format).
  - Use **Elliptic Curve Diffie-Hellman (ECDH)** algorithm to derive a shared secret.
  
- **Message Encryption and Decryption**:
  - Derive the AES key by hashing the shared secret.
  - Encrypt and decrypt messages using the generated AES key.

- **Elliptic Curves Used**:
  - `secp256r1`: Faster key exchange and encryption.
  - `secp384r1`: Offers higher security but comparatively slower operations.

## Steps Followed

### Key Generation

1. Select an elliptic curve (initially `secp256r1`).
2. Generate ECC public and private keys (EC points: pair of {x, y}).
3. Serialize and exchange public keys using Privacy Enhanced Mail (PEM) format.
4. Deserialize the received public key.
5. Use ECDH to derive a common shared secret.
6. Successfully establish the shared secret key.

### Encryption and Decryption

1. Generate ECC key pairs.
2. Exchange public keys and derive a shared secret using ECDH.
3. Hash the shared secret to generate the AES encryption key.
4. Encrypt and decrypt the message using AES.
5. Repeat the process by switching the elliptic curve to `secp384r1` to observe changes.

## Observations

- `secp256r1`:
  - Faster key exchange and AES operations.
  - Good balance of speed and security.

- `secp384r1`:
  - More secure due to a larger key size.
  - Slightly slower in operations compared to `secp256r1`.

## Technologies Used

- Python
- Cryptography Libraries (`cryptography` package)
- ECC (secp256r1 and secp384r1)
- AES (Advanced Encryption Standard)

## How to Run

1. Clone the repository:
    ```bash
    git clone https://github.com/your-username/ecc-aes-encryption.git
    cd ecc-aes-encryption
    ```

2. Install required packages:
    ```bash
    pip install cryptography
    ```

3. Run the script:
    ```bash
    python main.py
    ```

4. Follow the prompts to encrypt and decrypt your message.
