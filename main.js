import { Config } from './config.js';
import { concatBytes, decodeBase64URL, encodeBase64URL } from './crypto.js';
import { DB, Vault } from './storage.js';
import { withStateLock } from './locks.js';
import { formatEnvelope, parseEnvelope, parseHeader } from './codec.js';
import { calculateFingerprint, getLocalFingerprint, getLocalIdentity, serializeIdentityPublic, } from './identity.js';
import { CreateInit, EncryptMessage, ProcessInit, ProcessResp, DecryptMessage, } from './ratchet.js';
const State = {
    currentContactFp: undefined,
    showArchived: false,
    searchQuery: '',
};
let selectionSeq = 0;
let sidebarSeq = 0;
const mediaReaders = new Set();
function cancelMediaReads() {
    for (const reader of mediaReaders)
        reader.abort();
    mediaReaders.clear();
    UI.$('#media-input').value = '';
}
let toastTimer;
const UI = {
    $: (s) => {
        const el = document.querySelector(s);
        if (!el)
            throw new Error(`Required DOM element not found: ${s}`);
        return el;
    },
    showToast: (msg, duration = 3500) => {
        const t = UI.$('#toast');
        UI.$('#toast-msg').textContent = msg;
        t.classList.remove('opacity-0', 'pointer-events-none');
        t.classList.add('opacity-100');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => {
            t.classList.remove('opacity-100');
            t.classList.add('opacity-0', 'pointer-events-none');
        }, duration);
    },
    showModal: (containerHtml) => {
        if (!Vault.isUnlocked())
            return;
        UI.$('#modal-container').innerHTML = containerHtml;
        UI.$('#modal-overlay').classList.remove('hidden');
        UI.$('#modal-overlay').classList.add('flex');
    },
    closeModal: () => {
        UI.$('#modal-overlay').classList.remove('flex');
        UI.$('#modal-overlay').classList.add('hidden');
    },
    closeMetadata: () => {
        UI.$('#metadata-overlay').classList.add('hidden');
        UI.$('#metadata-overlay').classList.remove('flex');
    },
};
UI.$('#modal-overlay').onclick = () => UI.closeModal();
UI.$('#modal-container').onclick = (event) => event.stopPropagation();
UI.$('#metadata-overlay > div').onclick = (event) => event.stopPropagation();
const closePeerDropdown = () => UI.$('#peer-dropdown').classList.add('hidden');
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        UI.closeModal();
        UI.closeMetadata();
        closePeerDropdown();
    }
});
function resetChatView(updateHash = true) {
    selectionSeq++;
    renderSeq++;
    cancelMediaReads();
    UI.$('#chat-input').value = '';
    delete State.currentContactFp;
    if (updateHash && location.hash)
        history.replaceState(null, '', location.pathname + location.search);
    UI.$('#chat-view').classList.add('hidden');
    UI.$('#chat-view').classList.remove('flex');
    UI.$('#sidebar-view').classList.remove('max-md:hidden');
    UI.$('#chat-messages').replaceChildren();
    UI.$('#chat-title').textContent = 'Select a Peer';
    UI.$('#chat-status-text').textContent = 'Idle';
    UI.$('#chat-status-dot').className = 'w-2 h-2 rounded-full bg-slate-500';
    UI.$('#chat-input-area').classList.add('hidden');
    UI.$('#empty-state').classList.remove('hidden');
}
async function copyToClipboard(text, msg) {
    try {
        if (!Vault.isUnlocked())
            throw new Error('Vault is locked.');
        await navigator.clipboard.writeText(text);
        UI.showToast(msg);
    }
    catch (err) {
        if (!Vault.isUnlocked())
            return;
        console.warn('[Clipboard] Write error, falling back to modal:', err);
        UI.showModal(`
      <div class="p-4 border-b border-slate-800"><h3 class="font-bold text-slate-200">Manual Copy Required</h3></div>
      <div class="p-4 space-y-3">
        <p class="text-xs text-amber-400">Your browser blocked automatic clipboard access. Please copy the text below manually:</p>
        <div id="fallback-text" class="flex min-h-11 items-center rounded-lg border border-slate-800/80 bg-slate-950 p-3 font-mono text-[11px] break-all text-emerald-300 shadow-inner select-all"></div>
      </div>
      <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
        <button id="btn-close-fallback" class="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Done</button>
      </div>
    `);
        requestAnimationFrame(() => {
            if (Vault.isUnlocked())
                UI.$('#fallback-text').textContent = text;
        });
        UI.$('#btn-close-fallback').onclick = UI.closeModal;
    }
}
async function handleOutgoing(packetBase64, bundleBase64) {
    await copyToClipboard(formatEnvelope(decodeBase64URL(bundleBase64 ?? packetBase64)), `Encrypted ${typeof bundleBase64 !== 'undefined' ? 'Bundle' : 'Packet'} Copied`);
}
async function renderSidebar() {
    const sequence = ++sidebarSeq;
    const generation = uiGeneration;
    const identity = await getLocalIdentity();
    if (!Vault.isUnlocked() ||
        generation !== uiGeneration ||
        sequence !== sidebarSeq)
        return;
    UI.$('#my-fingerprint').textContent = calculateFingerprint(serializeIdentityPublic(identity));
    let contacts = await DB.getAll('contacts');
    if (!State.showArchived)
        contacts = contacts.filter(({ archived }) => !archived);
    const sessions = await DB.getAll('sessions');
    const frag = document.createDocumentFragment();
    for (const c of contacts) {
        const div = document.createElement('div');
        const isActive = c.fingerprint === State.currentContactFp;
        div.className = `min-h-11 p-3 rounded-lg cursor-pointer text-sm border transition-all duration-150 flex flex-col justify-center gap-1 ${isActive
            ? 'bg-indigo-900/40 border-indigo-500/50 text-indigo-100 shadow-sm'
            : 'bg-slate-900/80 border-slate-800 text-slate-300 hover:bg-slate-800/80 hover:border-slate-700'}`;
        let unreadCount = 0;
        if (!isActive) {
            const session = sessions.find(({ contactFp }) => contactFp === c.fingerprint);
            if (session)
                unreadCount = (await DB.getAllByIndex('messages', 'conversationId', session.conversationId)).filter(({ isMe, timestamp }) => !isMe && timestamp > c.lastReadTimestamp).length;
        }
        const topRow = document.createElement('div');
        topRow.className = 'flex justify-between items-center gap-2';
        const nameSpan = document.createElement('span');
        nameSpan.className = 'font-medium truncate flex-1';
        nameSpan.textContent = c.name;
        topRow.appendChild(nameSpan);
        if (unreadCount) {
            const badge = document.createElement('span');
            badge.className =
                'bg-emerald-500 text-slate-950 text-[10px] font-bold px-1.5 py-0.5 rounded-full shrink-0 shadow-sm';
            badge.textContent = `${unreadCount}`;
            topRow.appendChild(badge);
        }
        const botRow = document.createElement('div');
        botRow.className =
            'flex justify-between items-center text-[10px] text-slate-500 font-mono';
        const fpSpan = document.createElement('span');
        fpSpan.className = 'truncate';
        fpSpan.textContent = c.fingerprint;
        botRow.appendChild(fpSpan);
        if (c.archived) {
            const archSpan = document.createElement('span');
            archSpan.className = 'text-amber-400 font-sans';
            archSpan.textContent = '(Archived)';
            botRow.appendChild(archSpan);
        }
        div.appendChild(topRow);
        div.appendChild(botRow);
        div.onclick = () => selectContact(c.fingerprint);
        div.oncontextmenu = (e) => {
            e.preventDefault();
            showPeerMetadata(c.fingerprint);
        };
        frag.appendChild(div);
    }
    if (Vault.isUnlocked() &&
        generation === uiGeneration &&
        sequence === sidebarSeq)
        UI.$('#contacts-list').replaceChildren(frag);
}
async function selectContact(fp, isNavigatingHistory = false) {
    if (fp === State.currentContactFp)
        return;
    const selection = ++selectionSeq;
    const generation = uiGeneration;
    renderSeq++;
    cancelMediaReads();
    UI.$('#chat-input').value = '';
    UI.$('#chat-input-area').classList.add('hidden');
    const contact = await DB.get('contacts', fp);
    if (selection !== selectionSeq ||
        generation !== uiGeneration ||
        !Vault.isUnlocked())
        return;
    if (!contact) {
        resetChatView(true);
        return;
    }
    if (!isNavigatingHistory) {
        const targetHash = `#${fp}`;
        if (location.hash !== targetHash)
            if (State.currentContactFp)
                history.replaceState(null, '', targetHash);
            else
                history.pushState(null, '', targetHash);
    }
    State.currentContactFp = fp;
    UI.$('#chat-messages').replaceChildren();
    await updateContact(fp, (current) => {
        current.lastReadTimestamp = Date.now();
    });
    if (selection !== selectionSeq ||
        generation !== uiGeneration ||
        !Vault.isUnlocked())
        return;
    UI.$('#sidebar-view').classList.add('max-md:hidden');
    UI.$('#chat-view').classList.remove('hidden');
    UI.$('#chat-view').classList.add('flex');
    UI.$('#empty-state').classList.add('hidden');
    UI.$('#chat-input-area').classList.remove('hidden');
    UI.$('#chat-title').textContent = contact.name;
    closePeerDropdown();
    UI.$('#btn-archive-contact').textContent = contact.archived
        ? 'Restore Peer'
        : 'Archive Peer';
    State.searchQuery = '';
    UI.$('#chat-search-input').value = '';
    UI.$('#search-bar-container').classList.add('hidden');
    await renderChatLog(true);
    await renderSidebar();
}
let renderSeq = 0;
async function renderChatLog(isInitialView = false) {
    const contactFp = State.currentContactFp;
    if (!contactFp)
        return;
    const currentSeq = ++renderSeq;
    const generation = uiGeneration;
    const sessions = await DB.getAll('sessions');
    const session = sessions.find((candidate) => candidate.contactFp === contactFp);
    if (currentSeq !== renderSeq ||
        !Vault.isUnlocked() ||
        generation !== uiGeneration)
        return;
    if (session)
        if (session.state === 'HANDSHAKE_SENT' ||
            session.state === 'HANDSHAKE_RECEIVED') {
            UI.$('#chat-status-text').textContent =
                session.state === 'HANDSHAKE_SENT'
                    ? 'Awaiting RESP'
                    : 'Handshake Pending';
            UI.$('#chat-status-dot').className =
                'w-2 h-2 rounded-full bg-amber-400 animate-pulse';
            UI.$('#chat-input').disabled =
                UI.$('#media-input').disabled =
                    UI.$('#btn-attach').disabled =
                        session.state === 'HANDSHAKE_SENT';
        }
        else {
            UI.$('#chat-status-text').textContent = 'Channel Established';
            UI.$('#chat-status-dot').className =
                'w-2 h-2 rounded-full bg-emerald-400';
            UI.$('#chat-input').disabled =
                UI.$('#media-input').disabled =
                    UI.$('#btn-attach').disabled =
                        false;
        }
    else {
        UI.$('#chat-status-text').textContent = 'Idle';
        UI.$('#chat-status-dot').className = 'w-2 h-2 rounded-full bg-slate-500';
        UI.$('#chat-input').disabled =
            UI.$('#media-input').disabled =
                UI.$('#btn-attach').disabled =
                    false;
    }
    UI.$('#btn-start-session').disabled = Boolean(session);
    UI.$('#chat-input').disabled =
        session?.state !== 'ESTABLISHED';
    UI.$('#btn-attach').disabled =
        session?.state !== 'ESTABLISHED';
    UI.$('#chat-form button[type=submit]').disabled =
        session?.state !== 'ESTABLISHED';
    const query = State.searchQuery.toLowerCase();
    const highlightRegex = query
        ? new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi')
        : undefined;
    const allChatMsgs = session
        ? await DB.getAllByIndex('messages', 'conversationId', session.conversationId)
        : [];
    const chatMsgs = allChatMsgs.sort((a, b) => a.timestamp === b.timestamp
        ? a.id.localeCompare(b.id)
        : a.timestamp - b.timestamp);
    const ctn = UI.$('#chat-messages');
    const frag = document.createDocumentFragment();
    let displayedCount = 0;
    for (const m of chatMsgs) {
        if (query && !m.text.toLowerCase().includes(query))
            continue;
        displayedCount++;
        const div = document.createElement('div');
        div.className = `flex flex-col max-w-[85%] sm:max-w-[75%] p-3.5 rounded-2xl text-sm break-words shadow-sm border transition-all ${m.isMe
            ? 'bg-indigo-600 border-indigo-500/60 self-end rounded-br-xs text-indigo-50'
            : 'bg-slate-900 border-slate-800 self-start rounded-bl-xs text-slate-200'}`;
        if (m.text.startsWith('data:image/')) {
            const img = document.createElement('img');
            img.src = m.text;
            img.className = 'max-w-full max-h-80 rounded-lg object-contain my-1';
            div.appendChild(img);
        }
        else if (m.text.startsWith('data:video/')) {
            const vid = document.createElement('video');
            vid.src = m.text;
            vid.controls = true;
            vid.className = 'max-w-full max-h-80 rounded-lg object-contain my-1';
            div.appendChild(vid);
        }
        else if (m.text.startsWith('data:audio/')) {
            const aud = document.createElement('audio');
            aud.src = m.text;
            aud.controls = true;
            aud.className = 'max-w-full my-1';
            div.appendChild(aud);
        }
        else if (query && highlightRegex) {
            const span = document.createElement('span');
            div.appendChild(span);
            for (const part of m.text.split(highlightRegex))
                if (part.toLowerCase() === query) {
                    const partSpan = document.createElement('span');
                    partSpan.className =
                        'bg-amber-500/30 text-white rounded px-0.5 font-semibold';
                    partSpan.textContent = part;
                    span.appendChild(partSpan);
                }
                else
                    span.appendChild(document.createTextNode(part));
        }
        else
            div.textContent = m.text;
        const timeSpan = document.createElement('div');
        timeSpan.className = `text-[10px] mt-1.5 select-none flex justify-end ${m.isMe ? 'text-indigo-200/80' : 'text-slate-400'}`;
        timeSpan.textContent = new Date(m.timestamp).toLocaleString();
        div.appendChild(timeSpan);
        frag.appendChild(div);
    }
    if (query && !displayedCount) {
        const emptySearch = document.createElement('div');
        emptySearch.className =
            'flex flex-col items-center justify-center my-auto py-12 text-slate-500 text-xs';
        emptySearch.textContent = 'No matching messages found';
        frag.appendChild(emptySearch);
    }
    if (!Vault.isUnlocked() ||
        generation !== uiGeneration ||
        currentSeq !== renderSeq ||
        contactFp !== State.currentContactFp)
        return;
    ctn.replaceChildren(frag);
    if (isInitialView)
        ctn.scrollTop = ctn.scrollHeight;
    else
        requestAnimationFrame(() => {
            ctn.scrollTo({ top: ctn.scrollHeight, behavior: 'smooth' });
        });
}
UI.$('#btn-attach').onclick = () => UI.$('#media-input').click();
const submitChatMessage = async (mediaText, targetFp = State.currentContactFp, generation = uiGeneration, selection = selectionSeq) => {
    if (isSending ||
        !Vault.isUnlocked() ||
        generation !== uiGeneration ||
        selection !== selectionSeq ||
        targetFp !== State.currentContactFp)
        return;
    const input = UI.$('#chat-input');
    const text = mediaText ?? input.value.trim();
    if (!text || !targetFp)
        return;
    isSending = true;
    input.disabled = true;
    const submitBtn = UI.$('#chat-form button[type="submit"]');
    submitBtn.disabled = true;
    try {
        const { packet, session } = await EncryptMessage(targetFp, text);
        if (!Vault.isUnlocked())
            return;
        const response = session.lastRespPacket
            ? decodeBase64URL(session.lastRespPacket)
            : undefined;
        const bundle = response && response.length + packet.length <= Config.MAX_PACKET_SIZE
            ? encodeBase64URL(concatBytes(response, packet))
            : undefined;
        await handleOutgoing(encodeBase64URL(packet), bundle);
        if (selection === selectionSeq && generation === uiGeneration)
            input.value = '';
    }
    catch (err) {
        UI.showToast(`Crypto Error: ${err instanceof Error && err.message ? err.message : String(err)}`);
        console.error('[Crypto] Outgoing processing error:', err);
    }
    finally {
        isSending = false;
        submitBtn.disabled = false;
        if (Vault.isUnlocked())
            await renderChatLog();
        if (!input.disabled)
            input.focus();
    }
};
function sendMedia(file) {
    const targetFp = State.currentContactFp;
    const generation = uiGeneration;
    const selection = selectionSeq;
    if (!targetFp || !Vault.isUnlocked() || isSending)
        return;
    if (file.size > 700000) {
        UI.showToast('Media exceeds the 700 KB limit.');
        return;
    }
    const reader = new FileReader();
    mediaReaders.add(reader);
    reader.onload = () => {
        mediaReaders.delete(reader);
        if (selection !== selectionSeq ||
            generation !== uiGeneration ||
            !Vault.isUnlocked())
            return;
        if (typeof reader.result === 'string')
            void submitChatMessage(reader.result, targetFp, generation, selection);
        UI.$('#media-input').value = '';
    };
    reader.onabort = reader.onerror = () => {
        mediaReaders.delete(reader);
    };
    reader.readAsDataURL(file);
}
UI.$('#media-input').onchange = (e) => {
    const file = e.target.files?.[0];
    if (file)
        sendMedia(file);
};
UI.$('#chat-input').addEventListener('paste', (e) => {
    const items = e.clipboardData?.items;
    if (!items)
        return;
    for (const item of items)
        if (item.type.startsWith('image/') ||
            item.type.startsWith('video/') ||
            item.type.startsWith('audio/')) {
            e.preventDefault();
            const file = item.getAsFile();
            if (!file)
                continue;
            sendMedia(file);
            break;
        }
});
let isSending = false;
UI.$('#chat-form').onsubmit = (e) => {
    e.preventDefault();
    submitChatMessage();
};
UI.$('#btn-back-mobile').onclick = () => {
    history.back();
};
UI.$('#btn-copy-identity').onclick = async () => {
    await copyToClipboard(formatEnvelope(serializeIdentityPublic(await getLocalIdentity())), 'Identity Bundle Copied');
};
UI.$('#btn-add-contact').onclick = async () => {
    try {
        const text = await navigator.clipboard.readText();
        const bytes = parseEnvelope(text);
        if (bytes.length !== 4225)
            throw new Error('Invalid identity bundle.');
        const fp = calculateFingerprint(bytes);
        const localFp = await getLocalFingerprint();
        if (fp === localFp) {
            UI.showToast('Cannot link own identity.');
            return;
        }
        if (await DB.get('contacts', fp)) {
            UI.showToast('Peer already exists.');
            return;
        }
        UI.showModal(`
      <div class="p-4 bg-slate-900 border-b border-slate-800"><h3 class="font-bold text-slate-200">Link New Peer</h3></div>
      <div class="p-4">
        <label class="block text-xs text-slate-400 mb-1">Assign Local Alias</label>
        <input type="text" id="new-alias-input" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:border-indigo-500 outline-none min-h-11 text-base sm:text-sm transition-colors" placeholder="e.g. Work Laptop" />
        <p class="text-xs text-amber-300 mt-3">Compare this full fingerprint with your peer using a separate trusted channel. Do not trust a fingerprint sent alongside this bundle.</p>
        <div id="new-peer-fp" class="font-mono text-xs break-all select-all my-3"></div>
        <label class="block text-xs text-slate-400">Enter the fingerprint confirmed by your peer</label>
        <input id="verified-fp-input" autocomplete="off" class="w-full rounded border p-2 bg-slate-950" />
      </div>
      <div class="p-4 bg-slate-900 flex justify-end gap-2 border-t border-slate-800/50">
        <button id="btn-cancel-add" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
        <button id="btn-confirm-add" class="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Save Peer</button>
      </div>
    `);
        requestAnimationFrame(() => {
            const input = UI.$('#new-alias-input');
            if (input) {
                input.focus();
                input.onkeydown = (e) => {
                    if (e.key === 'Enter')
                        UI.$('#btn-confirm-add').click();
                };
            }
        });
        UI.$('#new-peer-fp').textContent = fp;
        UI.$('#btn-cancel-add').onclick = UI.closeModal;
        UI.$('#btn-confirm-add').onclick = async () => {
            try {
                const name = UI.$('#new-alias-input').value.trim();
                if (!name)
                    return;
                if (UI.$('#verified-fp-input').value.trim() !== fp) {
                    UI.showToast('The full fingerprint must match your independently confirmed value.');
                    return;
                }
                await withStateLock(async () => {
                    if (await DB.get('contacts', fp))
                        throw new Error('Peer already exists.');
                    await DB.put('contacts', {
                        fingerprint: fp,
                        bundle: encodeBase64URL(bytes),
                        name,
                        verified: true,
                        archived: false,
                        lastReadTimestamp: Date.now(),
                    });
                });
                UI.closeModal();
                UI.showToast('Peer linked successfully.');
                await renderSidebar();
            }
            catch (err) {
                UI.showToast('Failed to save peer.');
                console.error('[Storage] Save peer error:', err);
            }
        };
    }
    catch (err) {
        UI.showToast('Invalid identity format in clipboard.');
        console.error('[Clipboard] Parse identity error:', err);
    }
};
UI.$('#btn-toggle-archived').onclick = () => {
    State.showArchived = !State.showArchived;
    UI.$('#btn-toggle-archived').textContent = State.showArchived
        ? 'Hide Archived'
        : 'Show Archived';
    renderSidebar();
};
UI.$('#btn-peer-menu').onclick = () => UI.$('#peer-dropdown').classList.toggle('hidden');
document.addEventListener('click', (e) => {
    if (!UI.$('#btn-peer-menu').contains(e.target) &&
        !UI.$('#peer-dropdown').contains(e.target))
        closePeerDropdown();
});
UI.$('#btn-search-toggle').onclick = () => {
    const c = UI.$('#search-bar-container');
    c.classList.toggle('hidden');
    if (!c.classList.contains('hidden'))
        UI.$('#chat-search-input').focus();
    else {
        State.searchQuery = '';
        UI.$('#chat-search-input').value = '';
        renderChatLog();
    }
};
UI.$('#chat-search-input').oninput = (e) => {
    State.searchQuery = e.target.value;
    renderChatLog();
};
UI.$('#btn-rename-contact').onclick = async () => {
    closePeerDropdown();
    if (!State.currentContactFp)
        return;
    const contact = await DB.get('contacts', State.currentContactFp);
    if (!contact)
        return;
    UI.showModal(`
    <div class="p-4 border-b border-slate-800"><h3 class="font-bold text-slate-200">Rename Alias</h3></div>
    <div class="p-4"><input type="text" id="rename-val" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 min-h-11 text-base sm:text-sm text-slate-200 focus:border-indigo-500 outline-none transition-colors" /></div>
    <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
      <button id="btn-cancel" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
      <button id="btn-save" class="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Save</button>
    </div>
  `);
    requestAnimationFrame(() => {
        const input = UI.$('#rename-val');
        if (input) {
            input.value = contact.name;
            input.focus();
            input.onkeydown = (e) => {
                if (e.key === 'Enter')
                    UI.$('#btn-save').click();
            };
        }
    });
    UI.$('#btn-cancel').onclick = UI.closeModal;
    UI.$('#btn-save').onclick = async () => {
        try {
            contact.name =
                UI.$('#rename-val').value.trim() || contact.name;
            await updateContact(contact.fingerprint, (current) => {
                current.name = contact.name;
            });
            if (!Vault.isUnlocked())
                return;
            UI.$('#chat-title').textContent = contact.name;
            UI.closeModal();
            await renderSidebar();
        }
        catch (err) {
            UI.showToast('Failed to save alias.');
            console.error('[Storage] Rename contact error:', err);
        }
    };
};
UI.$('#btn-archive-contact').onclick = async () => {
    closePeerDropdown();
    if (!State.currentContactFp)
        return;
    try {
        const contact = await DB.get('contacts', State.currentContactFp);
        if (!contact)
            return;
        contact.archived = !contact.archived;
        UI.$('#btn-archive-contact').textContent = contact.archived
            ? 'Restore Peer'
            : 'Archive Peer';
        await updateContact(contact.fingerprint, (current) => {
            current.archived = contact.archived;
        });
        UI.showToast(contact.archived ? 'Peer archived.' : 'Peer restored.');
        await renderSidebar();
    }
    catch (err) {
        UI.showToast('Failed to update peer.');
        console.error('[Storage] Archive contact error:', err);
    }
};
UI.$('#btn-delete-contact').onclick = async () => {
    closePeerDropdown();
    if (!State.currentContactFp)
        return;
    const targetFp = State.currentContactFp;
    const session = await DB.get('sessions', targetFp);
    UI.showModal(`
    <div class="p-4 border-b border-red-900/50 bg-red-950/30"><h3 class="font-bold text-red-400">Confirm Deletion</h3></div>
    <div class="p-4 text-sm text-slate-300">${session
        ? 'Warning: This peer has an active channel. Deleting removes all stored sessions and history for this peer. Replay protection is retained.'
        : 'This removes the peer and all associated local history. It cannot erase copies held by the browser or other devices.'}</div>
    <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
      <button id="btn-cancel-del" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
      <button id="btn-confirm-del" class="px-4 py-2 text-sm bg-red-600 hover:bg-red-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Delete Peer</button>
    </div>
  `);
    UI.$('#btn-cancel-del').onclick = UI.closeModal;
    UI.$('#btn-confirm-del').onclick = async () => {
        try {
            await DB.deletePeer(targetFp);
            UI.closeModal();
            resetChatView(true);
            UI.showToast('Peer deleted.');
            await renderSidebar();
        }
        catch (err) {
            UI.showToast('Failed to delete peer.');
            console.error('[Storage] Delete contact error:', err);
        }
    };
};
UI.$('#btn-reset-session').onclick = async () => {
    closePeerDropdown();
    if (!State.currentContactFp)
        return;
    const targetFp = State.currentContactFp;
    const session = await DB.get('sessions', targetFp);
    if (!session)
        return;
    UI.showModal(`
    <div class="p-4 border-b border-amber-900/50 bg-amber-950/30"><h3 class="font-bold text-amber-400">Wipe Channel State?</h3></div>
    <div class="p-4 text-sm text-slate-300">This removes all session state and history for this peer. Your contact and replay protection are retained. Both peers must reset before starting a new handshake.</div>
    <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
      <button id="btn-cancel-wipe" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
      <button id="btn-confirm-wipe" class="px-4 py-2 text-sm bg-amber-600 hover:bg-amber-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Wipe</button>
    </div>
  `);
    UI.$('#btn-cancel-wipe').onclick = UI.closeModal;
    UI.$('#btn-confirm-wipe').onclick = async () => {
        try {
            await DB.deletePeer(targetFp, false);
            UI.closeModal();
            await renderChatLog();
            UI.showToast('Channel state wiped.');
        }
        catch (err) {
            UI.showToast('Failed to wipe channel.');
            console.error('[Storage] Wipe session error:', err);
        }
    };
};
UI.$('#btn-global-settings').onclick = () => {
    UI.showModal(`
    <div class="p-4 space-y-4"><h3 class="font-bold">Encrypted local vault</h3>
      <p class="text-sm">Keys and history are encrypted with your passphrase. The vault locks after five minutes of inactivity. There is no password recovery. The clipboard and exported packets are outside the vault.</p>
      <button id="btn-lock-vault" class="rounded bg-indigo-600 p-3">Lock now</button>
      <button id="btn-destroy-vault" class="rounded bg-red-900 p-3">Delete all local data</button>
    </div>`);
    UI.$('#btn-lock-vault').onclick = () => Vault.lock();
    UI.$('#btn-destroy-vault').onclick = async () => {
        if (!confirm('Delete this vault, identity, all peer histories and replay protection? This cannot be undone.'))
            return;
        try {
            await Vault.destroy();
            await showVaultScreen();
        }
        catch {
            UI.showToast('Deletion failed. Close other ECP tabs and try again.');
        }
    };
};
async function processClipboardText(rawText) {
    if (!Vault.isUnlocked())
        return;
    const text = rawText.trim();
    if (!text.startsWith(Config.PREFIX)) {
        UI.showToast('Invalid ECP envelope format.');
        return;
    }
    if (text.length >
        Math.ceil((Config.MAX_PACKET_SIZE * 4) / 3) + Config.PREFIX.length) {
        UI.showToast('Packet exceeds maximum size limits.');
        return;
    }
    try {
        const bytes = parseEnvelope(text);
        if (bytes[0] === Config.IDENTITY_VERSION && bytes.length === 4225) {
            UI.showToast("Identity bundle detected. Please use 'Link New Peer'.");
            return;
        }
        let offset = 0;
        let sessionChanged = false;
        let packetCount = 0;
        while (offset < bytes.length) {
            if (++packetCount > 8)
                throw new Error('Too many bundled packets.');
            if (bytes.length - offset < 12)
                throw new Error('Truncated packet header.');
            const { type, payloadLength } = parseHeader(bytes.slice(offset, offset + 12));
            if (payloadLength > Config.MAX_PACKET_SIZE)
                throw new Error('Payload size constraint violation.');
            const pktLen = 12 + payloadLength;
            if (bytes.length - offset < pktLen)
                throw new Error('Incomplete packet payload structure.');
            const pktBytes = bytes.slice(offset, offset + pktLen);
            offset += pktLen;
            try {
                if (type === Config.PACKET_TYPES.INIT) {
                    const { respPacket } = await ProcessInit(pktBytes);
                    if (!Vault.isUnlocked())
                        return;
                    UI.showToast('Handshake INIT processed.');
                    await handleOutgoing(encodeBase64URL(respPacket));
                    sessionChanged = true;
                }
                else if (type === Config.PACKET_TYPES.RESP) {
                    const { alreadyEstablished } = await ProcessResp(pktBytes);
                    if (alreadyEstablished)
                        console.warn('[Ratchet] Skipping redundant RESP packet in bundle.');
                    else {
                        UI.showToast('Channel established.');
                        sessionChanged = true;
                    }
                }
                else if (type === Config.PACKET_TYPES.MSG) {
                    await DecryptMessage(pktBytes);
                    if (!Vault.isUnlocked())
                        return;
                    UI.showToast('Message decrypted.');
                    sessionChanged = true;
                }
            }
            catch (err) {
                UI.showToast(`Packet rejected: ${err instanceof Error ? err.message : 'Invalid packet'}`);
                break;
            }
        }
        if (sessionChanged && Vault.isUnlocked()) {
            await renderChatLog();
            await renderSidebar();
        }
    }
    catch (err) {
        UI.showToast(`Bundle Rejected: ${err instanceof Error && err.message ? err.message : String(err)}`);
        console.error('[Ratchet] Incoming bundle error:', err);
    }
}
UI.$('#btn-read').onclick = UI.$('#btn-read-clipboard').onclick = async () => {
    try {
        const text = await navigator.clipboard.readText();
        await processClipboardText(text);
    }
    catch (err) {
        UI.showToast('Failed to read clipboard.');
        console.error('[Clipboard] Read error:', err);
    }
};
document.addEventListener('paste', async (e) => {
    if (!Vault.isUnlocked())
        return;
    if (['INPUT', 'TEXTAREA'].includes(e.target.tagName))
        return;
    const text = (e.clipboardData?.getData('text') ?? '').trim();
    if (!text.startsWith(Config.PREFIX))
        return;
    e.preventDefault();
    await processClipboardText(text);
});
async function showPeerMetadata(contactFp) {
    const session = await DB.get('sessions', contactFp);
    const contact = await DB.get('contacts', contactFp);
    if (!Vault.isUnlocked())
        return;
    UI.$('#metadata-title').textContent = 'Peer Diagnostics';
    UI.$('#metadata-content').innerHTML = `
    <div><strong>Peer FP:</strong> <span id="meta-fp"></span></div>
    <hr class="border-slate-800 my-2" />
    <div><strong>Double Ratchet State:</strong> <span id="meta-state" class="${session
        ? session.state === 'ESTABLISHED'
            ? 'text-emerald-400'
            : 'text-amber-400'
        : 'text-slate-500'}"></span></div>
    ${session
        ? `<div><strong>Conversation ID:</strong> <span id="meta-cid"></span></div>
    <div><strong>Message Sequence (Ns):</strong> <span id="meta-ns"></span></div>
    <div><strong>Receive Sequence (Nr):</strong> <span id="meta-nr"></span></div>
    <div><strong>Previous Chain Length (PN):</strong> <span id="meta-pn"></span></div>`
        : ''}`;
    UI.$('#meta-fp').textContent = contact ? contact.fingerprint : 'Unknown';
    UI.$('#meta-state').textContent = session ? session.state : 'IDLE';
    if (session) {
        UI.$('#meta-cid').textContent = session.conversationId;
        UI.$('#meta-ns').textContent = `${session.Ns}`;
        UI.$('#meta-nr').textContent = `${session.Nr}`;
        UI.$('#meta-pn').textContent = `${session.PN}`;
    }
    UI.$('#metadata-overlay').classList.remove('hidden');
    UI.$('#metadata-overlay').classList.add('flex');
}
UI.$('#metadata-overlay').onclick = () => UI.closeMetadata();
UI.$('#btn-close-metadata').onclick = () => UI.closeMetadata();
async function handleRoute() {
    if (!Vault.isUnlocked())
        return;
    const hash = location.hash.replace(/^#/, '').trim();
    if (!hash) {
        resetChatView(false);
        await renderSidebar();
        return;
    }
    if (hash === State.currentContactFp)
        return;
    await selectContact(hash, true);
}
addEventListener('hashchange', handleRoute);
let uiGeneration = 0;
let lockTimer;
let newVault = true;
let vaultScreenSeq = 0;
async function updateContact(fp, update) {
    return withStateLock(async () => {
        const contact = await DB.get('contacts', fp);
        if (!contact)
            throw new Error('Peer was removed.');
        update(contact);
        await DB.put('contacts', contact);
    });
}
function armAutoLock() {
    clearTimeout(lockTimer);
    if (Vault.isUnlocked())
        lockTimer = setTimeout(() => Vault.lock(), 5 * 60_000);
}
for (const name of ['pointerdown', 'keydown'])
    addEventListener(name, armAutoLock, { passive: true });
addEventListener('pagehide', () => Vault.lock());
addEventListener('ecp-vault-locked', () => {
    uiGeneration++;
    renderSeq++;
    clearTimeout(lockTimer);
    selectionSeq++;
    cancelMediaReads();
    delete State.currentContactFp;
    State.searchQuery = '';
    UI.$('#app-root').classList.add('hidden');
    UI.$('#vault-screen').classList.remove('hidden');
    UI.closeModal();
    UI.closeMetadata();
    for (const id of [
        'chat-messages',
        'contacts-list',
        'my-fingerprint',
        'metadata-content',
        'modal-container',
    ])
        UI.$(`#${id}`).replaceChildren();
    UI.$('#chat-title').textContent = 'Select a Peer';
    UI.$('#chat-input').value = '';
    UI.$('#chat-search-input').value = '';
    UI.$('#media-input').value = '';
    void showVaultScreen().catch(showStorageError);
});
function showStorageError() {
    if (!Vault.isUnlocked())
        UI.$('#vault-error').textContent =
            'Browser storage is unavailable. Close other ECP tabs and reload.';
}
async function showVaultScreen() {
    if (Vault.isUnlocked())
        return;
    const sequence = ++vaultScreenSeq;
    const generation = uiGeneration;
    UI.$('#app-root').classList.add('hidden');
    UI.$('#vault-screen').classList.remove('hidden');
    const status = await Vault.status();
    const hasLegacyData = await Vault.hasLegacyData();
    if (sequence !== vaultScreenSeq ||
        generation !== uiGeneration ||
        Vault.isUnlocked())
        return;
    newVault = status === 'new';
    UI.$('#vault-title').textContent = newVault
        ? 'Create your encrypted vault'
        : 'Unlock your vault';
    UI.$('#vault-submit').textContent = newVault ? 'Create vault' : 'Unlock';
    UI.$('#vault-confirm-label').classList.toggle('hidden', !newVault);
    UI.$('#vault-password').autocomplete = newVault
        ? 'new-password'
        : 'current-password';
    UI.$('#legacy-notice').classList.toggle('hidden', !hasLegacyData);
    if (!navigator.locks || !crypto.subtle) {
        UI.$('#vault-error').textContent =
            'Use a browser with Web Crypto and Web Locks over HTTPS or localhost.';
        UI.$('#vault-submit').disabled = true;
    }
}
UI.$('#vault-form').onsubmit = async (event) => {
    event.preventDefault();
    const password = UI.$('#vault-password');
    const confirmation = UI.$('#vault-confirm');
    const button = UI.$('#vault-submit');
    button.disabled = true;
    UI.$('#vault-error').textContent = '';
    try {
        if (newVault && password.value !== confirmation.value)
            throw new Error('Passphrases do not match.');
        if (newVault)
            await Vault.create(password.value);
        else
            await Vault.unlock(password.value);
        password.value = '';
        confirmation.value = '';
        await getLocalIdentity();
        await renderSidebar();
        if (!Vault.isUnlocked())
            throw new Error('Vault was locked. Unlock it to continue.');
        vaultScreenSeq++;
        UI.$('#vault-screen').classList.add('hidden');
        UI.$('#app-root').classList.remove('hidden');
        await handleRoute();
        armAutoLock();
    }
    catch (error) {
        UI.$('#vault-error').textContent =
            error instanceof Error && error.message
                ? error.message
                : 'Unable to unlock vault. Check your passphrase.';
    }
    finally {
        password.value = '';
        confirmation.value = '';
        button.disabled = false;
    }
};
UI.$('#btn-delete-legacy').onclick = async () => {
    if (!confirm('Delete all old ECP v1 unencrypted keys, contacts and history on this origin? There is no automatic migration or recovery.'))
        return;
    try {
        await Vault.deleteLegacyData();
        await showVaultScreen();
    }
    catch {
        UI.$('#vault-error').textContent =
            'Close old ECP tabs before deleting legacy data.';
    }
};
UI.$('#btn-start-session').onclick = async () => {
    const fp = State.currentContactFp;
    if (!fp || !Vault.isUnlocked())
        return;
    const button = UI.$('#btn-start-session');
    button.disabled = true;
    try {
        const { packet } = await CreateInit(fp);
        await handleOutgoing(encodeBase64URL(packet));
        await renderChatLog();
    }
    catch (error) {
        UI.showToast(error instanceof Error ? error.message : 'Handshake failed.');
        if (Vault.isUnlocked())
            await renderChatLog();
    }
};
void showVaultScreen().catch(showStorageError);
//# sourceMappingURL=main.js.map