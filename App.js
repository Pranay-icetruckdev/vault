import React, { useCallback, useEffect, useRef, useState } from 'react';
import { View, Text, TextInput, Pressable, FlatList, Modal, ScrollView, AppState, StyleSheet, Platform, ActivityIndicator } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Clipboard from 'expo-clipboard';
import { getRandomBytes } from 'expo-crypto';
import { scryptAsync } from '@noble/hashes/scrypt';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

/* ---------- crypto: scrypt key from master password + XChaCha20-Poly1305 ---------- */
const STORE = 'vault.v1';
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, dkLen: 32, asyncTick: 20 };
const deriveKey = (pw, salt) => scryptAsync(utf8ToBytes(pw.normalize('NFKC')), salt, SCRYPT);
const seal = (key, salt, items) => {
  const nonce = getRandomBytes(24);
  const ct = xchacha20poly1305(key, nonce).encrypt(utf8ToBytes(JSON.stringify(items)));
  return JSON.stringify({ v: 1, salt: bytesToHex(salt), nonce: bytesToHex(nonce), ct: bytesToHex(ct) });
};
const unseal = (key, blob) => {
  const b = JSON.parse(blob);
  const pt = xchacha20poly1305(key, hexToBytes(b.nonce)).decrypt(hexToBytes(b.ct)); // throws if wrong key / tampered
  return JSON.parse(new TextDecoder().decode(pt));
};
const generate = (n = 20) => {
  const cs = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_';
  const lim = 256 - (256 % cs.length);
  let out = '';
  while (out.length < n) for (const b of getRandomBytes(32)) if (b < lim && out.length < n) out += cs[b % cs.length];
  return out;
};
const copy = async (text, clearAfter = true) => {
  await Clipboard.setStringAsync(text);
  if (clearAfter) setTimeout(() => Clipboard.setStringAsync(''), 30000);
};

/* ---------- theme + small UI parts ---------- */
const C = { bg: '#F3F4F6', card: '#FFFFFF', ink: '#111318', mute: '#6B7280', line: '#E5E7EB', accent: '#3B5BDB', danger: '#D64545' };

const Btn = ({ label, onPress, kind = 'solid', disabled, style }) => (
  <Pressable onPress={onPress} disabled={disabled}
    style={({ pressed }) => [s.btn, kind === 'ghost' && s.btnGhost, kind === 'danger' && { backgroundColor: C.danger }, (disabled || pressed) && { opacity: 0.55 }, style]}>
    <Text style={[s.btnText, kind === 'ghost' && { color: C.ink }]}>{label}</Text>
  </Pressable>
);
const Field = ({ style, multiline, ...p }) => (
  <TextInput placeholderTextColor={C.mute} autoCapitalize="none" autoCorrect={false} spellCheck={false} multiline={multiline}
    style={[s.input, multiline && { minHeight: 96, textAlignVertical: 'top' }, style]} {...p} />
);
const Sheet = ({ children, onClose }) => (
  <Modal transparent animationType="fade" onRequestClose={onClose}>
    <View style={s.overlay}>
      <ScrollView contentContainerStyle={s.sheetWrap} keyboardShouldPersistTaps="handled">
        <View style={s.sheet}>{children}</View>
      </ScrollView>
    </View>
  </Modal>
);

/* ---------- master password screen (setup + unlock) ---------- */
function Gate({ setup, onSubmit }) {
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const go = async () => {
    if (setup && pw.length < 12) return setErr('Use at least 12 characters. A long phrase works well.');
    if (setup && pw !== pw2) return setErr('Passwords do not match.');
    setBusy(true); setErr('');
    const e = await onSubmit(pw);
    if (e) { setErr(e); setBusy(false); }
  };
  return (
    <View style={s.center}>
      <Text style={s.h1}>{setup ? 'Create your master password' : 'Unlock vault'}</Text>
      {setup && <Text style={s.note}>This password encrypts everything. It cannot be recovered if you forget it.</Text>}
      <Field placeholder="Master password" secureTextEntry value={pw} onChangeText={setPw} onSubmitEditing={go} />
      {setup && <Field placeholder="Repeat master password" secureTextEntry value={pw2} onChangeText={setPw2} onSubmitEditing={go} />}
      {!!err && <Text style={s.err}>{err}</Text>}
      {busy ? <ActivityIndicator color={C.accent} style={{ marginTop: 16 }} /> : <Btn label={setup ? 'Create vault' : 'Unlock'} onPress={go} style={{ marginTop: 8 }} />}
    </View>
  );
}

/* ---------- add / edit form ---------- */
function Editor({ item, onSave, onClose }) {
  const [d, setD] = useState(item || { type: 'password', title: '', user: '', secret: '', notes: '' });
  const [show, setShow] = useState(false);
  const set = (k) => (v) => setD((x) => ({ ...x, [k]: v }));
  const phrase = d.type === 'phrase';
  return (
    <Sheet onClose={onClose}>
      <Text style={s.h2}>{item ? 'Edit entry' : 'New entry'}</Text>
      <View style={s.seg}>
        {[['password', 'Password'], ['phrase', 'Recovery phrase']].map(([k, l]) => (
          <Pressable key={k} onPress={() => set('type')(k)} style={[s.segItem, d.type === k && s.segOn]}>
            <Text style={[s.segText, d.type === k && { color: C.ink, fontWeight: '600' }]}>{l}</Text>
          </Pressable>
        ))}
      </View>
      <Field placeholder={phrase ? 'Wallet name' : 'Site or app'} value={d.title} onChangeText={set('title')} />
      {!phrase && <Field placeholder="Username or email" value={d.user} onChangeText={set('user')} />}
      <Field placeholder={phrase ? 'Recovery phrase (12–24 words)' : 'Password'} value={d.secret} onChangeText={set('secret')}
        multiline={phrase} secureTextEntry={!phrase && !show} />
      {!phrase && (
        <View style={s.row}>
          <Btn kind="ghost" label={show ? 'Hide' : 'Show'} onPress={() => setShow(!show)} style={s.small} />
          <Btn kind="ghost" label="Generate" onPress={() => { set('secret')(generate()); setShow(true); }} style={[s.small, { marginLeft: 8 }]} />
        </View>
      )}
      <Field placeholder="Notes (optional)" value={d.notes} onChangeText={set('notes')} multiline />
      <View style={[s.row, { marginTop: 12 }]}>
        <Btn kind="ghost" label="Cancel" onPress={onClose} style={{ flex: 1 }} />
        <Btn label={item ? 'Review changes' : 'Save'} disabled={!d.title.trim() || !d.secret.trim()} onPress={() => onSave(d)} style={{ flex: 1, marginLeft: 8 }} />
      </View>
    </Sheet>
  );
}

/* ---------- two-step confirmation: 1) master password  2) type a word ---------- */
function TwoStep({ action, name, verify, onDone, onCancel }) {
  const del = action === 'delete';
  const word = del ? 'DELETE' : 'UPDATE';
  const [step, setStep] = useState(1);
  const [pw, setPw] = useState('');
  const [typed, setTyped] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const next = async () => {
    setBusy(true); setErr('');
    const ok = await verify(pw);
    setBusy(false);
    ok ? setStep(2) : setErr('Wrong master password.');
  };
  const finish = async () => { setBusy(true); await onDone(); };
  return (
    <Sheet onClose={onCancel}>
      <Text style={s.h2}>{del ? 'Delete' : 'Update'} “{name}”</Text>
      {step === 1 ? (
        <>
          <Text style={s.note}>Step 1 of 2. Enter your master password.</Text>
          <Field placeholder="Master password" secureTextEntry value={pw} onChangeText={setPw} onSubmitEditing={next} />
          {!!err && <Text style={s.err}>{err}</Text>}
        </>
      ) : (
        <>
          <Text style={s.note}>Step 2 of 2. Type {word} to confirm.{del ? ' This cannot be undone.' : ''}</Text>
          <Field placeholder={word} autoCapitalize="characters" value={typed} onChangeText={setTyped} />
        </>
      )}
      <View style={[s.row, { marginTop: 12 }]}>
        <Btn kind="ghost" label="Cancel" onPress={onCancel} style={{ flex: 1 }} />
        {step === 1
          ? <Btn label={busy ? 'Checking…' : 'Continue'} disabled={busy || !pw} onPress={next} style={{ flex: 1, marginLeft: 8 }} />
          : <Btn kind={del ? 'danger' : 'solid'} label={del ? 'Delete entry' : 'Update entry'} disabled={busy || typed.trim().toUpperCase() !== word} onPress={finish} style={{ flex: 1, marginLeft: 8 }} />}
      </View>
    </Sheet>
  );
}

/* ---------- encrypted backup: move your vault between phone and PC ---------- */
function Backup({ onExport, onImport, onClose }) {
  const [blob, setBlob] = useState('');
  const [pw, setPw] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <Sheet onClose={onClose}>
      <Text style={s.h2}>Backup and transfer</Text>
      <Text style={s.note}>The backup is encrypted. Without your master password it is unreadable, so it is safe to send to yourself.</Text>
      <Btn label="Copy encrypted backup" onPress={async () => { await onExport(); setMsg('Copied. Paste it into the vault on your other device.'); }} />
      <Text style={[s.note, { marginTop: 20 }]}>Import replaces the vault on this device. The imported vault keeps the master password it was created with.</Text>
      <Field placeholder="Paste backup text" value={blob} onChangeText={setBlob} multiline />
      <Field placeholder="Master password of that backup" secureTextEntry value={pw} onChangeText={setPw} />
      <Btn kind="ghost" label={busy ? 'Importing…' : 'Import backup'} disabled={busy || !blob || !pw}
        onPress={async () => { setBusy(true); const e = await onImport(blob, pw); setBusy(false); setMsg(e || 'Imported.'); }} />
      {!!msg && <Text style={[s.note, { marginTop: 8 }]}>{msg}</Text>}
      <Btn kind="ghost" label="Close" onPress={onClose} style={{ marginTop: 12 }} />
    </Sheet>
  );
}

/* ---------- vault list ---------- */
function Vault({ items, save, verify, lock, exportBackup, importBackup }) {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(null);
  const [reveal, setReveal] = useState(false);
  const [editing, setEditing] = useState(null); // null | 'new' | draft object
  const [pending, setPending] = useState(null);
  const [backup, setBackup] = useState(false);
  const list = items.filter((i) => (i.title + ' ' + (i.user || '')).toLowerCase().includes(q.toLowerCase()));

  const onSave = async (d) => {
    if (!d.id) { await save([{ ...d, id: bytesToHex(getRandomBytes(8)), updated: Date.now() }, ...items]); return setEditing(null); }
    setEditing(null);
    setPending({ action: 'edit', name: d.title, draft: d,
      run: () => save(items.map((i) => (i.id === d.id ? { ...d, updated: Date.now() } : i))) });
  };
  const toggle = (id) => { setOpen(open === id ? null : id); setReveal(false); };

  return (
    <View style={{ flex: 1 }}>
      <View style={[s.row, { marginBottom: 16 }]}>
        <Text style={[s.h1, { flex: 1, marginBottom: 0 }]}>Vault</Text>
        <Btn kind="ghost" label="Backup" onPress={() => setBackup(true)} style={s.small} />
        <Btn kind="ghost" label="Lock" onPress={lock} style={[s.small, { marginLeft: 8 }]} />
      </View>
      <Field placeholder="Search" value={q} onChangeText={setQ} />
      <FlatList data={list} keyExtractor={(i) => i.id} contentContainerStyle={{ paddingBottom: 96 }}
        ListEmptyComponent={<Text style={[s.note, { textAlign: 'center', marginTop: 40 }]}>{items.length ? 'No matches.' : 'Nothing saved yet. Add your first password or recovery phrase.'}</Text>}
        renderItem={({ item: it }) => (
          <Pressable onPress={() => toggle(it.id)} style={s.card}>
            <View style={s.row}>
              <View style={{ flex: 1 }}>
                <Text style={s.title}>{it.title}</Text>
                <Text style={s.sub}>{it.type === 'phrase' ? 'Recovery phrase' : it.user || 'Password'}</Text>
              </View>
              <Text style={s.sub}>{open === it.id ? 'Close' : 'Open'}</Text>
            </View>
            {open === it.id && (
              <View style={{ marginTop: 14 }}>
                <Text selectable={reveal} style={s.secret}>{reveal ? it.secret : '•'.repeat(14)}</Text>
                {!!it.notes && <Text style={[s.sub, { marginTop: 8 }]}>{it.notes}</Text>}
                <View style={[s.row, { marginTop: 14, flexWrap: 'wrap' }]}>
                  <Btn kind="ghost" label={reveal ? 'Hide' : 'Show'} onPress={() => setReveal(!reveal)} style={s.small} />
                  <Btn kind="ghost" label="Copy" onPress={() => copy(it.secret)} style={[s.small, { marginLeft: 8 }]} />
                  <Btn kind="ghost" label="Edit" onPress={() => setEditing(it)} style={[s.small, { marginLeft: 8 }]} />
                  <Btn kind="danger" label="Delete" onPress={() => setPending({ action: 'delete', name: it.title, run: () => save(items.filter((x) => x.id !== it.id)) })} style={[s.small, { marginLeft: 8 }]} />
                </View>
              </View>
            )}
          </Pressable>
        )} />
      <Btn label="Add entry" onPress={() => setEditing('new')} style={s.fab} />
      {editing && <Editor item={editing === 'new' ? null : editing} onSave={onSave} onClose={() => setEditing(null)} />}
      {pending && (
        <TwoStep action={pending.action} name={pending.name} verify={verify}
          onCancel={() => { if (pending.draft) setEditing(pending.draft); setPending(null); }}
          onDone={async () => { await pending.run(); setPending(null); setOpen(null); }} />
      )}
      {backup && <Backup onExport={exportBackup} onImport={importBackup} onClose={() => setBackup(false)} />}
    </View>
  );
}

/* ---------- app shell: session, auto-lock, persistence ---------- */
export default function App() {
  const [stage, setStage] = useState('loading'); // loading | setup | locked | open
  const [items, setItems] = useState([]);
  const session = useRef(null); // { key, salt } lives only in memory
  const idle = useRef(null);

  useEffect(() => { AsyncStorage.getItem(STORE).then((v) => setStage(v ? 'locked' : 'setup')); }, []);

  const lock = useCallback(() => { session.current = null; setItems([]); setStage((st) => (st === 'open' ? 'locked' : st)); }, []);
  const bump = useCallback(() => { clearTimeout(idle.current); idle.current = setTimeout(lock, 120000); }, [lock]);
  useEffect(() => {
    const sub = AppState.addEventListener('change', (st) => st !== 'active' && lock());
    return () => sub.remove();
  }, [lock]);
  useEffect(() => { stage === 'open' ? bump() : clearTimeout(idle.current); }, [stage, bump]);

  const save = async (next) => {
    await AsyncStorage.setItem(STORE, seal(session.current.key, session.current.salt, next));
    setItems(next);
  };
  const start = async (pw) => {
    try {
      const blob = await AsyncStorage.getItem(STORE);
      if (!blob) {
        const salt = getRandomBytes(16);
        session.current = { key: await deriveKey(pw, salt), salt };
        await save([]);
      } else {
        const salt = hexToBytes(JSON.parse(blob).salt);
        const key = await deriveKey(pw, salt);
        const list = unseal(key, blob);
        session.current = { key, salt };
        setItems(list);
      }
      setStage('open');
      return null;
    } catch { return 'Wrong master password.'; }
  };
  const verify = async (pw) => bytesToHex(await deriveKey(pw, session.current.salt)) === bytesToHex(session.current.key);
  const exportBackup = async () => copy(await AsyncStorage.getItem(STORE), false);
  const importBackup = async (text, pw) => {
    try {
      const blob = text.trim();
      const salt = hexToBytes(JSON.parse(blob).salt);
      const key = await deriveKey(pw, salt);
      const list = unseal(key, blob);
      session.current = { key, salt };
      await save(list);
      return null;
    } catch { return 'Could not open that backup. Check the text and its master password.'; }
  };

  return (
    <View style={s.root} onTouchStart={stage === 'open' ? bump : undefined} onPointerDown={stage === 'open' ? bump : undefined}>
      <View style={s.page}>
        {stage === 'loading' && <ActivityIndicator color={C.accent} style={{ marginTop: 80 }} />}
        {(stage === 'setup' || stage === 'locked') && <Gate key={stage} setup={stage === 'setup'} onSubmit={start} />}
        {stage === 'open' && <Vault items={items} save={save} verify={verify} lock={lock} exportBackup={exportBackup} importBackup={importBackup} />}
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: C.bg, alignItems: 'center', paddingTop: Platform.OS === 'web' ? 32 : 60 },
  page: { flex: 1, width: '100%', maxWidth: 520, paddingHorizontal: 20 },
  center: { flex: 1, justifyContent: 'center', paddingBottom: 80 },
  row: { flexDirection: 'row', alignItems: 'center' },
  h1: { fontSize: 28, fontWeight: '700', color: C.ink, letterSpacing: -0.5, marginBottom: 12 },
  h2: { fontSize: 20, fontWeight: '700', color: C.ink, marginBottom: 12 },
  note: { fontSize: 14, color: C.mute, lineHeight: 20, marginBottom: 12 },
  err: { fontSize: 14, color: C.danger, marginBottom: 8 },
  input: { backgroundColor: C.card, borderWidth: 1, borderColor: C.line, borderRadius: 10, paddingHorizontal: 14, paddingVertical: 12, fontSize: 16, color: C.ink, marginBottom: 10 },
  btn: { backgroundColor: C.accent, borderRadius: 10, paddingVertical: 13, paddingHorizontal: 18, alignItems: 'center' },
  btnGhost: { backgroundColor: C.card, borderWidth: 1, borderColor: C.line },
  btnText: { color: '#fff', fontSize: 15, fontWeight: '600' },
  small: { paddingVertical: 8, paddingHorizontal: 14 },
  card: { backgroundColor: C.card, borderRadius: 14, borderWidth: 1, borderColor: C.line, padding: 16, marginTop: 10 },
  title: { fontSize: 16, fontWeight: '600', color: C.ink },
  sub: { fontSize: 13, color: C.mute, marginTop: 2 },
  secret: { fontSize: 16, color: C.ink, letterSpacing: 0.3, lineHeight: 24 },
  fab: { position: 'absolute', bottom: 24, left: 20, right: 20 },
  overlay: { flex: 1, backgroundColor: 'rgba(17,19,24,0.45)' },
  sheetWrap: { flexGrow: 1, justifyContent: 'center', alignItems: 'center', padding: 20 },
  sheet: { width: '100%', maxWidth: 460, backgroundColor: C.bg, borderRadius: 14, padding: 20 },
  seg: { flexDirection: 'row', backgroundColor: C.line, borderRadius: 10, padding: 3, marginBottom: 12 },
  segItem: { flex: 1, paddingVertical: 8, alignItems: 'center', borderRadius: 8 },
  segOn: { backgroundColor: C.card },
  segText: { fontSize: 14, color: C.mute },
});