import type { Message } from './types.js';

export const TRANSIENT_MESSAGE_LIMIT = 100;
export const TRANSIENT_BYTE_LIMIT = 8 * 1024 * 1024;

// The budget counts UTF-16 string contents plus scalar fields, not engine heap
// overhead. This page owns the cache; it is never persisted or broadcast.
const messageBytes = (message: Message) =>
  2 *
    (message.text.length +
      message.id.length +
      message.contactFp.length +
      message.conversationId.length) +
  16;

export class TransientHistory {
  private entries = new Map<string, { message: Message; bytes: number }>();
  private bytes = 0;
  private revision = 0;
  private clearedAt = 0;
  private peerClearedAt = new Map<string, number>();

  // A result already pending when its peer is cleared must not repopulate the
  // page after the clearing transaction completes, including in another tab.
  captureWrite(): (message: Message) => void {
    const revision = this.revision;
    return (message) => {
      if (
        revision < this.clearedAt ||
        revision < (this.peerClearedAt.get(message.contactFp) ?? 0)
      )
        return;
      this.add(message);
    };
  }

  add(message: Message) {
    this.remove(message.id);
    const bytes = messageBytes(message);
    if (bytes > TRANSIENT_BYTE_LIMIT) return;
    while (
      this.entries.size >= TRANSIENT_MESSAGE_LIMIT ||
      this.bytes + bytes > TRANSIENT_BYTE_LIMIT
    )
      this.remove(this.entries.keys().next().value!);
    this.entries.set(message.id, {
      message: Object.freeze({ ...message }),
      bytes,
    });
    this.bytes += bytes;
  }

  forConversation(contactFp: string, conversationId: string): Message[] {
    return Array.from(this.entries.values(), ({ message }) => message).filter(
      (message) =>
        message.contactFp === contactFp &&
        message.conversationId === conversationId,
    );
  }

  clearPeer(contactFp: string) {
    this.peerClearedAt.set(contactFp, ++this.revision);
    for (const [id, { message }] of this.entries)
      if (message.contactFp === contactFp) this.remove(id);
  }

  clear() {
    this.clearedAt = ++this.revision;
    this.peerClearedAt.clear();
    this.entries.clear();
    this.bytes = 0;
  }

  private remove(id: string) {
    const entry = this.entries.get(id);
    if (entry) {
      this.bytes -= entry.bytes;
      this.entries.delete(id);
    }
  }
}
