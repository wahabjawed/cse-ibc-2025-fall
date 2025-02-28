// node-crypto-example.js

const crypto = require('crypto');

// Get name from command line arguments
const name = process.argv[2];

if (!name) {
    console.error("Please provide a name as a command line argument. Example: node node-crypto-example.js 'Your Name'");
    process.exit(1);
}

console.log("Name:", name);

// 1. Generate RSA Key Pair (2048 bits)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki', // Subject Public Key Info (standard PEM format)
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8', // PKCS#8 standard PEM format
        format: 'pem'
    }
});

console.log("\n--- RSA Key Pair (2048 bits) ---");
console.log("Public Key (PEM):");
console.log(publicKey);
console.log("\nPrivate Key (PEM): (Keep this SECRET!)");
console.log(privateKey); // In a real application, store this securely, NOT in console.log!


// 2. Hash Your Name (SHA-256, RIPEMD-160, SHA3)
console.log("\n--- Hashing Your Name ---");

// SHA-256
const sha256Hash = crypto.createHash('sha256').update(name).digest('hex');
console.log("SHA-256 Hash (HEX):", sha256Hash);

// RIPEMD-160
const ripemd160Hash = crypto.createHash('ripemd160').update(name).digest('hex');
console.log("RIPEMD-160 Hash (HEX):", ripemd160Hash);

// SHA3-256 (using 'sha3-256' - you might need to adjust if you want a different SHA3 variant)
const sha3Hash = crypto.createHash('sha3-256').update(name).digest('hex');
console.log("SHA3-256 Hash (HEX):", sha3Hash);


// 3. Encrypt Your Name with RSA Assymetric Algorithm (using Public Key)
console.log("\n--- RSA Encryption (using Public Key) ---");

// OAEP padding is generally recommended for new applications for better security.
// However, for basic demonstration, PKCS1_PADDING is also common and simpler to understand.
// We will use PKCS1_PADDING for simplicity in this example, but consider OAEP for production.
const encryptedNameBuffer = crypto.publicEncrypt({
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PADDING // or crypto.constants.RSA_PKCS1_OAEP_PADDING for OAEP
    // oaepHash: 'sha256'  // Required if using RSA_PKCS1_OAEP_PADDING
}, Buffer.from(name)); // Input data must be a Buffer

const encryptedNameBase64 = encryptedNameBuffer.toString('base64'); // Base64 encode for easier handling/display
console.log("Encrypted Name (Base64 encoded):", encryptedNameBase64);


// 4. Digital Signature (PKCS#1 v1.5)(SHA-256) - Sign Your Name with RSA Private Key
console.log("\n--- Digital Signature (PKCS#1 v1.5, SHA-256) ---");

const signer = crypto.createSign('SHA256');
signer.update(name);
const signatureBuffer = signer.sign({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING // PKCS#1 v1.5 padding as requested
});

const signatureBase64 = signatureBuffer.toString('base64'); // Base64 encode for easier handling/display
console.log("Digital Signature (Base64 encoded):", signatureBase64);


// 5. Bitcoin Wallet Address (This is a SIMPLIFIED placeholder - NOT a real address generator)
console.log("\n--- Bitcoin Wallet Address (Simplified Placeholder - NOT a real address generator) ---");

function generateSimplifiedBitcoinAddressPlaceholder(rsaPublicKeyPem) {
    // In REAL Bitcoin: You would hash the *ECDSA* public key, not RSA.
    // We are using the RSA public key from the example as a stand-in for demonstration.

    // Corrected line: Remove 'pem' encoding as PEM string is already in publicKey
    const publicKeyBuffer = Buffer.from(rsaPublicKeyPem); // Convert PEM string to buffer.

    // 1. SHA-256 hash of the Public Key (in Bitcoin, it's usually the *compressed* public key)
    const sha256HashOfPubKey = crypto.createHash('sha256').update(publicKeyBuffer).digest();

    // 2. RIPEMD-160 hash of the SHA-256 hash
    const ripemd160HashOfSha256 = crypto.createHash('ripemd160').update(sha256HashOfPubKey).digest('hex');

    // 3. Add version byte (0x00 for Main Network '1' addresses - simplified)
    const versionByte = '00'; // Mainnet version byte in hex
    const versionedPayload = versionByte + ripemd160HashOfSha256;

    // 4. **No Checksum is added in this simplified example for brevity.**
    //    Real Bitcoin addresses include a checksum.

    // 5. Base58 Encoding (Simplified - using hex for now for simplicity)
    //    Real Bitcoin uses Base58 encoding. For this placeholder, we'll just use Hex to keep it simple.
    const simplifiedBitcoinAddress = versionedPayload; // Already in hex string.

    return simplifiedBitcoinAddress;
}

const bitcoinAddressPlaceholder = generateSimplifiedBitcoinAddressPlaceholder(publicKey);
console.log("Bitcoin Wallet Address (Placeholder):", bitcoinAddressPlaceholder);
console.log("Note: This is a highly simplified and INVALID Bitcoin address placeholder.");
console.log("      A real Bitcoin address generation is much more complex and involves ECDSA keys,");
console.log("      compressed public keys, checksums, and Base58 encoding.");


console.log("\n--- Summary ---");
console.log("Name:", name);
console.log("Public Key (PEM):", publicKey.trim()); // Trim to remove extra newline at the end
console.log("SHA-256 Hash:", sha256Hash);
console.log("RIPEMD-160 Hash:", ripemd160Hash);
console.log("SHA3-256 Hash:", sha3Hash);
console.log("Encrypted Name (RSA, Base64):", encryptedNameBase64);
console.log("Digital Signature (RSA PKCS#1 v1.5, SHA-256, Base64):", signatureBase64);
console.log("Bitcoin Wallet Address (Placeholder):", bitcoinAddressPlaceholder); // Display the placeholder


/*
--- How to Run ---
1. Save this code as `node-crypto-example.js`
2. Open your terminal and navigate to the directory where you saved the file.
3. Run the command:  `node node-crypto-example.js "Your Name Here"`
   (Replace "Your Name Here" with your actual name)

--- Important Notes ---
* **Security:** This is a basic example for demonstration.
    * **Private Key Handling:** In a real application, NEVER log your private key to the console or store it insecurely. Use proper key management practices.
    * **Encryption Padding:**  For RSA encryption, consider using `crypto.constants.RSA_PKCS1_OAEP_PADDING` with `oaepHash: 'sha256'` for better security in new applications instead of `RSA_PKCS1_PADDING`.
    * **Bitcoin Address:** The "Bitcoin Wallet Address" section is just a placeholder. Generating a valid Bitcoin address is significantly more complex and involves steps not covered in this basic crypto example. It usually starts with hashing the *public key* (specifically, after applying ECDSA in Bitcoin's case, and then further hashing and encoding). This example focuses on demonstrating RSA and hashing primitives.

* **Dependencies:** This code uses Node.js built-in `crypto` module, so you don't need to install any external libraries.

* **Output Formats:**
    * **Public/Private Keys:** Output in PEM format (standard text-based encoding).
    * **Hashes:** Output in HEX encoded strings.
    * **Encrypted Name and Signature:** Output in Base64 encoded strings (to represent binary data in text).
    * **Bitcoin Wallet Address (Placeholder):** Output in HEX string (simplified).

* **SHA3 Variant:**  This example uses `sha3-256`. There are other SHA3 variants (like SHA3-512, SHA3-384). If you need a different one, adjust the `crypto.createHash('sha3-256')` accordingly (e.g., `crypto.createHash('sha3-512')`).
*/