import { LRUCache } from "./lru-cache.js";
import libsignal from "libsignal";
import { generateSignalPubKey } from "../Utils/index.js";
import {
    isHostedLidUser,
    isHostedPnUser,
    isLidUser,
    isPnUser,
    jidDecode,
    transferDevice,
    WAJIDDomains,
} from "../WABinary/index.js";
import { SenderKeyName } from "./Group/sender-key-name.js";
import { SenderKeyRecord } from "./Group/sender-key-record.js";
import {
    GroupCipher,
    GroupSessionBuilder,
    SenderKeyDistributionMessage
} from "./Group/index.js";
import { LIDMappingStore } from "./lid-mapping.js";

export function makeLibSignalRepository(auth, logger, pnToLIDFunc) {
    const lidMapping = new LIDMappingStore(auth.keys, logger, pnToLIDFunc);
    const storage = signalStorage(auth, lidMapping);
    const parsedKeys = auth.keys;

    const migratedSessionCache = new LRUCache({
        ttl: 3 * 24 * 60 * 60 * 1000,
        ttlAutopurge: true,
        updateAgeOnGet: true,
    });

    const repository = {
        decryptGroupMessage({ group, authorJid, msg }) {
            const senderName = jidToSignalSenderKeyName(group, authorJid);
            const cipher = new GroupCipher(storage, senderName);
            return parsedKeys.transaction(() => cipher.decrypt(msg), group);
        },

        async processSenderKeyDistributionMessage({ item, authorJid }) {
            if (!item.groupId) throw new Error("Group ID is required");
            const senderName = jidToSignalSenderKeyName(item.groupId, authorJid);
            const senderMsg = new SenderKeyDistributionMessage(
                null, null, null, null,
                item.axolotlSenderKeyDistributionMessage
            );

            const senderNameStr = senderName.toString();
            const { [senderNameStr]: senderKey } = await auth.keys.get("sender-key", [senderNameStr]);
            if (!senderKey) await storage.storeSenderKey(senderName, new SenderKeyRecord());

            const builder = new GroupSessionBuilder(storage);
            return parsedKeys.transaction(async () => {
                const { [senderNameStr]: senderKeyInner } = await auth.keys.get("sender-key", [senderNameStr]);
                if (!senderKeyInner) await storage.storeSenderKey(senderName, new SenderKeyRecord());
                await builder.process(senderName, senderMsg);
            }, item.groupId);
        },

        async decryptMessage({ jid, type, ciphertext }) {
            const addr = jidToSignalProtocolAddress(jid);
            const session = new libsignal.SessionCipher(storage, addr);

            const doDecrypt = async () => {
                switch (type) {
                    case "pkmsg":
                        return await session.decryptPreKeyWhisperMessage(ciphertext);
                    case "msg":
                        return await session.decryptWhisperMessage(ciphertext);
                    default:
                        throw new Error(`Unknown message type: ${type}`);
                }
            };

            return parsedKeys.transaction(() => doDecrypt(), jid);
        },

        async encryptMessage({ jid, data }) {
            const addr = jidToSignalProtocolAddress(jid);
            const cipher = new libsignal.SessionCipher(storage, addr);

            return parsedKeys.transaction(async () => {
                const { type: sigType, body } = await cipher.encrypt(data);
                const type = sigType === 3 ? "pkmsg" : "msg";
                return { type, ciphertext: Buffer.from(body, "binary") };
            }, jid);
        },

        async encryptGroupMessage({ group, meId, data }) {
            const senderName = jidToSignalSenderKeyName(group, meId);
            const builder = new GroupSessionBuilder(storage);
            const senderNameStr = senderName.toString();

            return parsedKeys.transaction(async () => {
                const { [senderNameStr]: senderKey } = await auth.keys.get("sender-key", [senderNameStr]);
                if (!senderKey) await storage.storeSenderKey(senderName, new SenderKeyRecord());

                const senderKeyDistributionMessage = await builder.create(senderName);
                const session = new GroupCipher(storage, senderName);
                const ciphertext = await session.encrypt(data);

                return {
                    ciphertext,
                    senderKeyDistributionMessage: senderKeyDistributionMessage.serialize(),
                };
            }, group);
        },

        async injectE2ESession({ jid, session }) {
            logger.trace({ jid }, "injecting E2EE session");
            const cipher = new libsignal.SessionBuilder(storage, jidToSignalProtocolAddress(jid));
            return parsedKeys.transaction(() => cipher.initOutgoing(session), jid);
        },

        lidMapping,

        async validateSession(jid) {
            try {
                const addr = jidToSignalProtocolAddress(jid);
                const session = await storage.loadSession(addr);
                if (!session) return { exists: false, reason: "no session" };
                if (!session.haveOpenSession()) return { exists: false, reason: "no open session" };
                return { exists: true };
            } catch {
                return { exists: false, reason: "validation error" };
            }
        },

        async deleteSession(jids) {
            if (!jids.length) return;
            const sessionUpdates = {};
            for (const jid of jids) {
                const addr = jidToSignalProtocolAddress(jid);
                sessionUpdates[addr.toString()] = null;
            }
            return parsedKeys.transaction(() => auth.keys.set({ session: sessionUpdates }), `delete-${jids.length}-sessions`);
        },

        async migrateSession(fromJid, toJid) {
            if (!fromJid || (!isLidUser(toJid) && !isHostedLidUser(toJid))) return { migrated: 0, skipped: 0, total: 0 };
            if (!isPnUser(fromJid) && !isHostedPnUser(fromJid)) return { migrated: 0, skipped: 0, total: 1 };

            const { user } = jidDecode(fromJid);
            const { [user]: userDevices } = await parsedKeys.get("device-list", [user]);
            if (!userDevices) return { migrated: 0, skipped: 0, total: 0 };

            const uncachedDevices = userDevices.filter(d => !migratedSessionCache.has(`${user}.${d}`));
            const deviceSessionKeys = uncachedDevices.map(d => `${user}.${d}`);
            const existingSessions = await parsedKeys.get("session", deviceSessionKeys);

            const migrationOps = [];
            for (const [sessionKey, sessionData] of Object.entries(existingSessions)) {
                if (!sessionData) continue;
                const deviceStr = sessionKey.split(".")[1];
                const deviceNum = parseInt(deviceStr);
                let jidStr = deviceNum === 0 ? `${user}@s.whatsapp.net` :
                             deviceNum === 99 ? `${user}:99@hosted` :
                             `${user}:${deviceNum}@s.whatsapp.net`;

                const lidWithDevice = transferDevice(jidStr, toJid);
                migrationOps.push({
                    fromJid: jidStr,
                    toJid: lidWithDevice,
                    fromAddr: jidToSignalProtocolAddress(jidStr),
                    toAddr: jidToSignalProtocolAddress(lidWithDevice),
                    deviceId: deviceNum,
                    pnUser: user,
                });
            }

            const sessionUpdates = {};
            let migratedCount = 0;
            for (const op of migrationOps) {
                const fromSession = existingSessions[`${op.pnUser}.${op.deviceId}`] ?
                    libsignal.SessionRecord.deserialize(existingSessions[`${op.pnUser}.${op.deviceId}`]) : null;
                if (fromSession && fromSession.haveOpenSession()) {
                    sessionUpdates[op.toAddr.toString()] = fromSession.serialize();
                    sessionUpdates[op.fromAddr.toString()] = null;
                    migratedCount++;
                    migratedSessionCache.set(`${op.pnUser}.${op.deviceId}`, true);
                }
            }

            if (Object.keys(sessionUpdates).length > 0) await parsedKeys.set({ session: sessionUpdates });

            return { migrated: migratedCount, skipped: migrationOps.length - migratedCount, total: migrationOps.length };
        },
    };

    return repository;
}

const jidToSignalProtocolAddress = (jid) => {
    const decoded = jidDecode(jid);
    const { user, device, domainType, server } = decoded;
    if (!user) throw new Error(`JID decoded but user empty: ${jid}`);

    const signalUser = domainType !== WAJIDDomains.WHATSAPP ? `${user}_${domainType}` : user;
    const finalDevice = device || 0;

    if (device === 99 && server !== "hosted" && server !== "hosted.lid")
        throw new Error("Unexpected non-hosted device JID with device 99: " + jid);

    return new libsignal.ProtocolAddress(signalUser, finalDevice);
};

const jidToSignalSenderKeyName = (group, user) => new SenderKeyName(group, jidToSignalProtocolAddress(user));

function signalStorage({ creds, keys }, lidMapping) {
    const resolveLIDSignalAddress = async id => {
        if (id.includes(".")) {
            const [deviceId, device] = id.split(".");
            const [user, domainType_] = deviceId.split("_");
            const domainType = parseInt(domainType_ || "0");

            if (domainType === WAJIDDomains.LID || domainType === WAJIDDomains.HOSTED_LID) return id;

            const pnJid = `${user}${device !== "0" ? `:${device}` : ""}@${domainType === WAJIDDomains.HOSTED ? "hosted" : "s.whatsapp.net"}`;
            const lidForPN = await lidMapping.getLIDForPN(pnJid);
            if (lidForPN) return jidToSignalProtocolAddress(lidForPN);
        }
        return id;
    };

    return {
        loadSession: async id => {
            try {
                const wireJid = await resolveLIDSignalAddress(id);
                const { [wireJid]: sess } = await keys.get("session", [wireJid]);
                return sess ? libsignal.SessionRecord.deserialize(sess) : null;
            } catch { return null; }
        },
        storeSession: async (id, session) => {
            const wireJid = await resolveLIDSignalAddress(id);
            await keys.set({ session: { [wireJid]: session.serialize() } });
        },
        isTrustedIdentity: () => true,
        loadPreKey: async id => {
            const { [id]: key } = await keys.get("pre-key", [id]);
            return key ? { privKey: Buffer.from(key.private), pubKey: Buffer.from(key.public) } : undefined;
        },
        removePreKey: id => keys.set({ "pre-key": { [id]: null } }),
        loadSignedPreKey: () => {
            const key = creds.signedPreKey;
            return { privKey: Buffer.from(key.keyPair.private), pubKey: Buffer.from(key.keyPair.public) };
        },
        loadSenderKey: async senderKeyName => {
            const keyId = senderKeyName.toString();
            const { [keyId]: key } = await keys.get("sender-key", [keyId]);
            return key ? SenderKeyRecord.deserialize(key) : new SenderKeyRecord();
        },
        storeSenderKey: async (senderKeyName, key) => {
            const keyId = senderKeyName.toString();
            await keys.set({ "sender-key": { [keyId]: Buffer.from(JSON.stringify(key.serialize()), "utf-8") } });
        },
        getOurRegistrationId: () => creds.registrationId,
        getOurIdentity: () => {
            const { signedIdentityKey } = creds;
            return { privKey: Buffer.from(signedIdentityKey.private), pubKey: Buffer.from(generateSignalPubKey(signedIdentityKey.public)) };
        },
    };
}