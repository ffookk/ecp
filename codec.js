import { Config } from './config.js';
import { decodeBase64URL, encodeBase64URL } from './crypto.js';
export const encodeUTF8 = (v) => new TextEncoder().encode(v);
export const decodeUTF8 = (v) => new TextDecoder('utf-8', { fatal: true }).decode(v);
export const zeros = (size) => new Uint8Array(size);
export const buildHeader = (type, payloadLength) => {
    if (!Number.isSafeInteger(payloadLength) ||
        payloadLength < 0 ||
        payloadLength + 12 > Config.MAX_PACKET_SIZE)
        throw new Error('Packet exceeds maximum size limits.');
    const hdr = zeros(12);
    hdr.set(Config.PACKET_MAGIC, 0);
    hdr[4] = Config.WIRE_PROTOCOL_VERSION;
    hdr[5] = type;
    new DataView(hdr.buffer).setUint32(8, payloadLength);
    return hdr;
};
export const parseHeader = (bytes) => {
    if (bytes.length < 12)
        throw new Error('Invalid packet length.');
    for (let i = 0; i < 4; i++)
        if (bytes[i] !== Config.PACKET_MAGIC[i])
            throw new Error('Packet magic byte mismatch.');
    if (bytes[4] !== Config.WIRE_PROTOCOL_VERSION)
        throw new Error('Unsupported wire protocol version.');
    if (bytes[6] || bytes[7])
        throw new Error('Reserved header fields must be zero.');
    if (![1, 2, 3].includes(bytes[5]))
        throw new Error('Unknown packet type.');
    return {
        type: bytes[5],
        payloadLength: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8),
        headerBytes: bytes.slice(0, 12),
    };
};
export const validatePacket = (bytes, expectedType) => {
    const header = parseHeader(bytes);
    if (bytes.length > Config.MAX_PACKET_SIZE ||
        header.payloadLength !== bytes.length - 12)
        throw new Error('Invalid packet size or trailing data.');
    if (expectedType !== undefined && header.type !== expectedType)
        throw new Error('Protocol type mismatch.');
    return header;
};
export const formatEnvelope = (bytes) => `${Config.PREFIX}${encodeBase64URL(bytes)}`;
export const parseEnvelope = (str) => {
    const trimmed = str.trim();
    if (!trimmed.startsWith(Config.PREFIX))
        throw new Error('Invalid ECP envelope format.');
    const encoded = trimmed.substring(Config.PREFIX.length);
    if (encoded.length > Math.ceil((Config.MAX_PACKET_SIZE * 4) / 3) ||
        !/^[A-Za-z0-9_-]+$/.test(encoded))
        throw new Error('Invalid or oversized ECP envelope.');
    const bytes = decodeBase64URL(encoded);
    if (bytes.length > Config.MAX_PACKET_SIZE ||
        encodeBase64URL(bytes) !== encoded)
        throw new Error('Noncanonical or oversized ECP envelope.');
    return bytes;
};
//# sourceMappingURL=codec.js.map