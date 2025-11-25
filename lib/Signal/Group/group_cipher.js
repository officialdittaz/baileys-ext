import { crypto } from "libsignal";
import { SenderKeyMessage } from "./sender-key-message.js";
import { SenderKeyName } from "./sender-key-name.js";
import { SenderKeyRecord } from "./sender-key-record.js";
import { SenderKeyState } from "./sender-key-state.js";
const { decrypt, encrypt } = crypto;

export class GroupCipher {
    constructor(senderKeyStore, senderKeyName) {
        this.senderKeyStore = senderKeyStore;
        this.senderKeyName = senderKeyName;
    }

    async encrypt(paddedPlaintext) {
        if (!paddedPlaintext || paddedPlaintext.length === 0) {
            throw new Error("Invalid plaintext for encryption");
        }

        const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName);
        if (!record) {
            throw new Error("No SenderKeyRecord found for encryption");
        }

        const senderKeyState = record.getSenderKeyState();
        if (!senderKeyState) {
            throw new Error("No session to encrypt message");
        }

        const iteration = senderKeyState.getSenderChainKey().getIteration();
        const senderKey = this.getSenderKey(senderKeyState, iteration === 0 ? 0 : iteration + 1);
        const ciphertext = await this.getCipherText(
            senderKey.getIv(),
            senderKey.getCipherKey(),
            paddedPlaintext
        );

        const senderKeyMessage = new SenderKeyMessage(
            senderKeyState.getKeyId(),
            senderKey.getIteration(),
            ciphertext,
            senderKeyState.getSigningKeyPrivate()
        );

        await this.senderKeyStore.storeSenderKey(this.senderKeyName, record);
        return senderKeyMessage.serialize();
    }

    async decrypt(senderKeyMessageBytes) {
        // Validate input
        if (!senderKeyMessageBytes || senderKeyMessageBytes.length === 0) {
            throw new Error("Invalid message bytes for decryption");
        }

        // Minimum message size check (version + keyId + iteration + ciphertext + signature)
        if (senderKeyMessageBytes.length < 50) {
            throw new Error(`Message too short for decryption: ${senderKeyMessageBytes.length} bytes`);
        }

        let record;
        try {
            record = await this.senderKeyStore.loadSenderKey(this.senderKeyName);
        } catch (error) {
            throw new Error(`Failed to load sender key: ${error.message}`);
        }

        if (!record) {
            throw new Error(
                `No SenderKeyRecord found for decryption (sender: ${this.senderKeyName.getSender()}, ` +
                `groupId: ${this.senderKeyName.getGroupId()}, deviceId: ${this.senderKeyName.getDeviceId()})`
            );
        }

        let senderKeyMessage;
        try {
            senderKeyMessage = new SenderKeyMessage(
                null,
                null,
                null,
                null,
                senderKeyMessageBytes
            );
        } catch (error) {
            throw new Error(`Failed to parse SenderKeyMessage: ${error.message}. Data length: ${senderKeyMessageBytes.length}`);
        }

        const keyId = senderKeyMessage.getKeyId();
        const iteration = senderKeyMessage.getIteration();
        
        const senderKeyState = record.getSenderKeyState(keyId);
        
        if (!senderKeyState) {
            // More detailed error for debugging
            const availableStates = record.getSenderKeyStates ? 
                record.getSenderKeyStates().map(s => s.getKeyId()).join(', ') : 
                'unknown';
            
            throw new Error(
                `No session found to decrypt message. ` +
                `Requested keyId: ${keyId}, iteration: ${iteration}. ` +
                `Available keyIds: [${availableStates}]. ` +
                `Sender: ${this.senderKeyName.getSender()}`
            );
        }

        // Verify signature before attempting decryption
        try {
            senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic());
        } catch (error) {
            throw new Error(`Message signature verification failed: ${error.message}`);
        }

        let senderKey;
        try {
            senderKey = this.getSenderKey(senderKeyState, iteration);
        } catch (error) {
            throw new Error(`Failed to get sender key for iteration ${iteration}: ${error.message}`);
        }

        let plaintext;
        try {
            plaintext = await this.getPlainText(
                senderKey.getIv(),
                senderKey.getCipherKey(),
                senderKeyMessage.getCipherText()
            );
        } catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }

        // Store updated record
        try {
            await this.senderKeyStore.storeSenderKey(this.senderKeyName, record);
        } catch (error) {
            // Log but don't fail - decryption was successful
            console.warn(`Failed to store updated sender key: ${error.message}`);
        }

        return plaintext;
    }

    getSenderKey(senderKeyState, iteration) {
        if (typeof iteration !== 'number' || iteration < 0) {
            throw new Error(`Invalid iteration value: ${iteration}`);
        }

        let senderChainKey = senderKeyState.getSenderChainKey();
        
        if (!senderChainKey) {
            throw new Error("Sender chain key is null or undefined");
        }

        const currentIteration = senderChainKey.getIteration();

        if (currentIteration > iteration) {
            if (senderKeyState.hasSenderMessageKey(iteration)) {
                const messageKey = senderKeyState.removeSenderMessageKey(iteration);
                if (!messageKey) {
                    throw new Error(`No sender message key found for iteration ${iteration}`);
                }
                return messageKey;
            }
            throw new Error(
                `Received message with old counter: current=${currentIteration}, received=${iteration}. ` +
                `This may indicate a duplicate or out-of-order message.`
            );
        }

        const iterationGap = iteration - currentIteration;
        if (iterationGap > 2000) {
            throw new Error(
                `Message iteration too far in future: gap=${iterationGap}, ` +
                `current=${currentIteration}, received=${iteration}`
            );
        }

        // Store intermediate message keys
        while (senderChainKey.getIteration() < iteration) {
            senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey());
            senderChainKey = senderChainKey.getNext();
            
            if (!senderChainKey) {
                throw new Error("Chain key advancement returned null");
            }
        }

        senderKeyState.setSenderChainKey(senderChainKey.getNext());
        return senderChainKey.getSenderMessageKey();
    }

    async getPlainText(iv, key, ciphertext) {
        if (!iv || !key || !ciphertext) {
            throw new Error("Missing required decryption parameters");
        }

        try {
            return await decrypt(key, ciphertext, iv);
        } catch (e) {
            throw new Error(`Decryption operation failed: ${e.message}`);
        }
    }

    async getCipherText(iv, key, plaintext) {
        if (!iv || !key || !plaintext) {
            throw new Error("Missing required encryption parameters");
        }

        try {
            return await encrypt(key, plaintext, iv);
        } catch (e) {
            throw new Error(`Encryption operation failed: ${e.message}`);
        }
    }
}