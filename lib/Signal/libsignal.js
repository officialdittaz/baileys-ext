import { LRUCache } from "./lru-cache.js";
import {
	GroupCipher,
	GroupSessionBuilder,
	ProtocolAddress,
	SenderKeyDistributionMessage,
	SenderKeyName,
	SessionBuilder,
	SessionCipher,
	SessionRecord
} from 'whatsapp-rust-bridge';
import {
	isHostedLidUser,
	isHostedPnUser,
	isLidUser,
	isPnUser,
	jidDecode,
	transferDevice,
	WAJIDDomains
} from '../WABinary';
import { LIDMappingStore } from './lid-mapping';

export function makeLibSignalRepository(auth, logger, pnToLIDFunc) {
	const lidMapping = new LIDMappingStore(auth.keys, logger, pnToLIDFunc);
	const storage = signalStorage(auth, lidMapping);
	const parsedKeys = auth.keys;
	const migratedSessionCache = new LRUCache({
		ttl: 3 * 24 * 60 * 60 * 1000,
		ttlAutopurge: true,
		updateAgeOnGet: true
	});

	const repository = {
		decryptGroupMessage({ group, authorJid, msg }) {
			const senderAddr = new ProtocolAddress(jidDecode(authorJid).user, jidDecode(authorJid).device || 0);
			const cipher = new GroupCipher(storage, group, senderAddr);
			return parsedKeys.transaction(async () => cipher.decrypt(msg), group);
		},

		async processSenderKeyDistributionMessage({ item, authorJid }) {
			const builder = new GroupSessionBuilder(storage);
			if (!item.groupId) throw new Error('Group ID is required for sender key distribution message');
			const senderAddr = new ProtocolAddress(jidDecode(authorJid).user, jidDecode(authorJid).device || 0);
			const senderName = new SenderKeyName(item.groupId, senderAddr);
			const senderMsg = SenderKeyDistributionMessage.deserialize(item.axolotlSenderKeyDistributionMessage);
			return parsedKeys.transaction(async () => {
				await builder.process(senderName, senderMsg);
			}, item.groupId);
		},

		async decryptMessage({ jid, type, ciphertext }) {
			const addr = jidToSignalProtocolAddress(jid);
			const session = new SessionCipher(storage, addr);
			async function doDecrypt() {
				let result;
				switch (type) {
					case 'pkmsg':
						result = await session.decryptPreKeyWhisperMessage(ciphertext);
						break;
					case 'msg':
						result = await session.decryptWhisperMessage(ciphertext);
						break;
				}
				return result;
			}
			return parsedKeys.transaction(async () => await doDecrypt(), jid);
		},

		async encryptMessage({ jid, data }) {
			const addr = jidToSignalProtocolAddress(jid);
			const cipher = new SessionCipher(storage, addr);
			return parsedKeys.transaction(async () => {
				const { type: sigType, body } = await cipher.encrypt(data);
				const type = sigType === 3 ? 'pkmsg' : 'msg';
				return { type, ciphertext: body };
			}, jid);
		},

		async encryptGroupMessage({ group, meId, data }) {
			const builder = new GroupSessionBuilder(storage);
			const meAddr = new ProtocolAddress(jidDecode(meId).user, jidDecode(meId).device || 0);
			const senderName = jidToSignalSenderKeyName(group, meId);
			const senderKeyDistributionMessage = await builder.create(senderName);
			const cipher = new GroupCipher(storage, group, meAddr);
			return parsedKeys.transaction(async () => {
				const ciphertext = await cipher.encrypt(data);
				return {
					ciphertext,
					senderKeyDistributionMessage: senderKeyDistributionMessage.serialize()
				};
			}, group);
		},

		async injectE2ESession({ jid, session }) {
			logger.trace({ jid }, 'injecting E2EE session');
			const cipher = new SessionBuilder(storage, jidToSignalProtocolAddress(jid));
			return parsedKeys.transaction(async () => {
				await cipher.initOutgoing(session);
			}, jid);
		},

		jidToSignalProtocolAddress(jid) {
			return jidToSignalProtocolAddress(jid).toString();
		},

		lidMapping,

		async validateSession(jid) {
			try {
				const addr = jidToSignalProtocolAddress(jid);
				const session = await storage.loadSession(addr.toString());
				if (!session) return { exists: false, reason: 'no session' };
				return { exists: true };
			} catch (error) {
				return { exists: false, reason: 'validation error' };
			}
		},

		async deleteSession(jids) {
			if (!jids.length) return;
			const sessionUpdates = {};
			jids.forEach(jid => {
				const addr = jidToSignalProtocolAddress(jid);
				sessionUpdates[addr.toString()] = null;
			});
			return parsedKeys.transaction(async () => {
				await auth.keys.set({ session: sessionUpdates });
			}, `delete-${jids.length}-sessions`);
		},

		async migrateSession(fromJid, toJid) {
			if (!fromJid || (!isLidUser(toJid) && !isHostedLidUser(toJid))) return { migrated: 0, skipped: 0, total: 0 };
			if (!isPnUser(fromJid) && !isHostedPnUser(fromJid)) return { migrated: 0, skipped: 0, total: 1 };
			const { user } = jidDecode(fromJid);
			logger.debug({ fromJid }, 'bulk device migration - loading all user devices');
			const { [user]: userDevices } = await parsedKeys.get('device-list', [user]);
			if (!userDevices) return { migrated: 0, skipped: 0, total: 0 };
			const { device: fromDevice } = jidDecode(fromJid);
			const fromDeviceStr = fromDevice?.toString() || '0';
			if (!userDevices.includes(fromDeviceStr)) userDevices.push(fromDeviceStr);
			const uncachedDevices = userDevices.filter(d => !migratedSessionCache.has(`${user}.${d}`));
			const deviceSessionKeys = uncachedDevices.map(d => `${user}.${d}`);
			const existingSessions = await parsedKeys.get('session', deviceSessionKeys);
			const deviceJids = [];
			for (const [sessionKey, sessionData] of Object.entries(existingSessions)) {
				if (sessionData) {
					const deviceStr = sessionKey.split('.')[1];
					if (!deviceStr) continue;
					const deviceNum = parseInt(deviceStr);
					let jidStr = deviceNum === 0 ? `${user}@s.whatsapp.net` : `${user}:${deviceNum}@s.whatsapp.net`;
					if (deviceNum === 99) jidStr = `${user}:99@hosted`;
					deviceJids.push(jidStr);
				}
			}
			logger.debug({ fromJid, totalDevices: userDevices.length, devicesWithSessions: deviceJids.length, devices: deviceJids }, 'bulk device migration complete - all user devices processed');
			return parsedKeys.transaction(async () => {
				const migrationOps = deviceJids.map(jid => {
					const lidWithDevice = transferDevice(jid, toJid);
					const fromDecoded = jidDecode(jid);
					const toDecoded = jidDecode(lidWithDevice);
					return {
						fromJid: jid,
						toJid: lidWithDevice,
						pnUser: fromDecoded.user,
						lidUser: toDecoded.user,
						deviceId: fromDecoded.device || 0,
						fromAddr: jidToSignalProtocolAddress(jid),
						toAddr: jidToSignalProtocolAddress(lidWithDevice)
					};
				});
				const totalOps = migrationOps.length;
				let migratedCount = 0;
				const pnAddrStrings = Array.from(new Set(migrationOps.map(op => op.fromAddr.toString())));
				const pnSessions = await parsedKeys.get('session', pnAddrStrings);
				const sessionUpdates = {};
				for (const op of migrationOps) {
					const pnAddrStr = op.fromAddr.toString();
					const lidAddrStr = op.toAddr.toString();
					const pnSession = pnSessions[pnAddrStr];
					if (pnSession) {
						const fromSession = SessionRecord.deserialize(pnSession);
						if (fromSession.haveOpenSession()) {
							sessionUpdates[lidAddrStr] = fromSession.serialize();
							sessionUpdates[pnAddrStr] = null;
							migratedCount++;
						}
					}
				}
				if (Object.keys(sessionUpdates).length > 0) {
					await parsedKeys.set({ session: sessionUpdates });
					logger.debug({ migratedSessions: migratedCount }, 'bulk session migration complete');
					for (const op of migrationOps) {
						if (sessionUpdates[op.toAddr.toString()]) migratedSessionCache.set(`${op.pnUser}.${op.deviceId}`, true);
					}
				}
				const skippedCount = totalOps - migratedCount;
				return { migrated: migratedCount, skipped: skippedCount, total: totalOps };
			}, `migrate-${deviceJids.length}-sessions-${jidDecode(toJid)?.user}`);
		}
	};

	return repository;
}

const jidToSignalProtocolAddress = jid => {
	const decoded = jidDecode(jid);
	const { user, device, server, domainType } = decoded;
	if (!user) throw new Error(`JID decoded but user is empty: "${jid}" -> user: "${user}", server: "${server}", device: ${device}`);
	const signalUser = domainType !== WAJIDDomains.WHATSAPP ? `${user}_${domainType}` : user;
	const finalDevice = device || 0;
	if (device === 99 && decoded.server !== 'hosted' && decoded.server !== 'hosted.lid') throw new Error('Unexpected non-hosted device JID with device 99: ' + jid);
	return new ProtocolAddress(signalUser, finalDevice);
};

const jidToSignalSenderKeyName = (group, user) => new SenderKeyName(group, jidToSignalProtocolAddress(user));

function signalStorage({ creds, keys }, lidMapping) {
	const resolveLIDSignalAddress = async id => {
		if (id.includes('.')) {
			const [deviceId, device] = id.split('.');
			const [user, domainType_] = deviceId.split('_');
			const domainType = parseInt(domainType_ || '0');
			if (domainType === WAJIDDomains.LID || domainType === WAJIDDomains.HOSTED_LID) return id;
			const pnJid = `${user}${device !== '0' ? `:${device}` : ''}@${domainType === WAJIDDomains.HOSTED ? 'hosted' : 's.whatsapp.net'}`;
			const lidForPN = await lidMapping.getLIDForPN(pnJid);
			if (lidForPN) return jidToSignalProtocolAddress(lidForPN).toString();
		}
		return id;
	};

	return {
		loadSession: async id => {
			try {
				const wireJid = await resolveLIDSignalAddress(id);
				const { [wireJid]: sess } = await keys.get('session', [wireJid]);
				return sess ?? null;
			} catch {
				return null;
			}
		},
		storeSession: async (id, session) => {
			const wireJid = await resolveLIDSignalAddress(id);
			await keys.set({ session: { [wireJid]: session.serialize() } });
		},
		isTrustedIdentity: () => true,
		loadPreKey: async id => {
			const { [id]: key } = await keys.get('pre-key', [id]);
			if (key) return { privKey: key.private, pubKey: key.public };
		},
		removePreKey: id => keys.set({ 'pre-key': { [id]: null } }),
		loadSignedPreKey: async id => {
			const key = creds.signedPreKey;
			if (!key || key.keyId !== id) return null;
			return { keyId: key.keyId, signature: key.signature, keyPair: { pubKey: key.keyPair.public, privKey: key.keyPair.private } };
		},
		loadSenderKey: async keyId => {
			const { [keyId]: key } = await keys.get('sender-key', [keyId]);
			return key ?? null;
		},
		storeSenderKey: async (keyId, keyBytes) => {
			await keys.set({ 'sender-key': { [keyId]: keyBytes.slice() } });
		},
		getOurRegistrationId: () => creds.registrationId,
		getOurIdentity: () => ({ privKey: creds.signedIdentityKey.private, pubKey: creds.signedIdentityKey.public })
	};
}