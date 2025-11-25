import { curve } from "libsignal";

/**
 * Generate a random 32-byte sender key (symmetric key for group encryption)
 */
export function generateSenderKey() {
    return Buffer.from(curve.generateKeyPair().privKey);
}

/**
 * Generate a random sender key ID (integer < 2^31)
 */
export function generateSenderKeyId() {
    return Math.floor(Math.random() * 0x7fffffff); // max signed 32-bit int
}

/**
 * Generate a sender signing key pair (EC key for signing sender key messages)
 * If no key provided, generates a new one
 */
export function generateSenderSigningKey(key) {
    if (!key) {
        key = curve.generateKeyPair();
    }
    return {
        public: Buffer.from(key.pubKey),
        private: Buffer.from(key.privKey),
    };
}