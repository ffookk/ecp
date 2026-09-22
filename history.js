export const TRANSIENT_MESSAGE_LIMIT = 100;
export const TRANSIENT_BYTE_LIMIT = 8 * 1024 * 1024;
const messageBytes = (message) => 2 *
    (message.text.length +
        message.id.length +
        message.contactFp.length +
        message.conversationId.length) +
    16;
export class TransientHistory {
    entries = new Map();
    bytes = 0;
    revision = 0;
    clearedAt = 0;
    peerClearedAt = new Map();
    captureWrite() {
        const revision = this.revision;
        return (message) => {
            if (revision < this.clearedAt ||
                revision < (this.peerClearedAt.get(message.contactFp) ?? 0))
                return;
            this.add(message);
        };
    }
    add(message) {
        this.remove(message.id);
        const bytes = messageBytes(message);
        if (bytes > TRANSIENT_BYTE_LIMIT)
            return;
        while (this.entries.size >= TRANSIENT_MESSAGE_LIMIT ||
            this.bytes + bytes > TRANSIENT_BYTE_LIMIT)
            this.remove(this.entries.keys().next().value);
        this.entries.set(message.id, {
            message: Object.freeze({ ...message }),
            bytes,
        });
        this.bytes += bytes;
    }
    forConversation(contactFp, conversationId) {
        return Array.from(this.entries.values(), ({ message }) => message).filter((message) => message.contactFp === contactFp &&
            message.conversationId === conversationId);
    }
    clearPeer(contactFp) {
        this.peerClearedAt.set(contactFp, ++this.revision);
        for (const [id, { message }] of this.entries)
            if (message.contactFp === contactFp)
                this.remove(id);
    }
    clear() {
        this.clearedAt = ++this.revision;
        this.peerClearedAt.clear();
        this.entries.clear();
        this.bytes = 0;
    }
    remove(id) {
        const entry = this.entries.get(id);
        if (entry) {
            this.bytes -= entry.bytes;
            this.entries.delete(id);
        }
    }
}
//# sourceMappingURL=history.js.map