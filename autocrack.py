#!/usr/bin/env python3
"""
Dependencies:  pip install pefile capstone
Usage:         python autocrack.py <target.exe> [--dry-run] [--verbose]
"""

import sys
import os
import struct
import argparse
from dataclasses import dataclass
from typing import List, Optional, Set, Dict, Tuple
from datetime import datetime

import pefile
import capstone
from capstone import x86_const

BANNER = r"""
    +=======================================+
    |   AutoCrack -- License Cracker        |
    |   Made by XEROX3                      |
    +=======================================+
"""

# -----------------------------------------------
#  String classification
# -----------------------------------------------

FAILURE_KEYWORDS = [
    "login failed",     "login error",      "login incorrect",
    "authentication failed", "auth failed",  "auth error",
    "license invalid",  "invalid license",  "license expired",
    "license failed",   "license error",    "license denied",
    "not licensed",     "license has expired", "license revoked",
    "license verification failed",
    "invalid key",      "wrong key",        "key is not valid",
    "key invalid",      "invalid serial",   "wrong serial",
    "key expired",      "key rejected",     "bad key",
    "invalid license key",
    "registration failed", "not registered", "unregistered",
    "registration error",
    "activation failed", "activation error", "not activated",
    "trial expired",    "trial ended",      "evaluation expired",
    "demo expired",     "time limit",
    "access denied",    "permission denied", "unauthorized",
    "verification failed", "check failed",
    "invalid credentials", "bad credentials",
    "login denied",     "session expired",
]

SUCCESS_KEYWORDS = [
    "welcome",      "license valid",  "license accepted",  "key accepted",
    "registered to", "licensed to",   "activation successful",
    "registration complete", "successfully activated", "authenticated",
    "thank you",    "valid key",     "license ok",  "key verified",
    "unlocked",     "full version",  "pro version", "premium",
    "registration successful", "success!",  "login successful",
    "logged in",    "access granted", "verified",
]

PROMPT_KEYWORDS = [
    "enter your license", "enter your key", "enter key",
    "enter serial",     "enter your serial", "enter code",
    "please enter",     "please register",  "please activate",
    "input your",       "type your key",    "paste your",
    "license key:",     "serial number:",   "product key:",
    "activation code:", "registration key:",
]

IGNORE_KEYWORDS = [
    "ssl", "tls", "sec_e_", "sec_i_", "schannel", "certificate",
    "x509", "pkcs", "cipher", "handshake", "curl_",
    "sspi", "gssapi", "socks5", "negotiate", "ntlm", "kerberos",
    "sasl", "preauth", "keyauth",
    "invalid string position", "string too long", "bad allocation",
    "out of range", "bad_alloc", "vector too long",
    "invalid literal", "invalid distance", "invalid block",
    "invalid code", "inflate", "deflate", "zlib",
    "invalid parameter", "invalid argument", "invalid handle",
    "signature verification",  # crypto lib internals
    "remote resource", "remote access",  # network lib noise
]


@dataclass
class Patch:
    file_offset: int
    size: int
    old_bytes: bytes
    new_bytes: bytes
    strategy: str       # "NOP", "FORCE_JMP", "JMP_TO_SUCCESS"
    reason: str


# -----------------------------------------------
#  Helpers
# -----------------------------------------------

_JCC_IDS = {
    x86_const.X86_INS_JE, x86_const.X86_INS_JNE,
    x86_const.X86_INS_JA, x86_const.X86_INS_JAE,
    x86_const.X86_INS_JB, x86_const.X86_INS_JBE,
    x86_const.X86_INS_JG, x86_const.X86_INS_JGE,
    x86_const.X86_INS_JL, x86_const.X86_INS_JLE,
    x86_const.X86_INS_JS, x86_const.X86_INS_JNS,
    x86_const.X86_INS_JO, x86_const.X86_INS_JNO,
    x86_const.X86_INS_JP, x86_const.X86_INS_JNP,
}

_BLOCK_ENDERS = {
    x86_const.X86_INS_JMP, x86_const.X86_INS_RET,
    x86_const.X86_INS_RETF, x86_const.X86_INS_INT3,
    x86_const.X86_INS_HLT,
}

def rva_to_offset(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return 0

def offset_to_rva(pe, offset):
    for s in pe.sections:
        if s.PointerToRawData <= offset < s.PointerToRawData + s.SizeOfRawData:
            return s.VirtualAddress + (offset - s.PointerToRawData)
    return 0

def hexdump(data):
    return ' '.join(f'{b:02X}' for b in data)

def get_jcc_target(ins):
    for op in ins.operands:
        if op.type == x86_const.X86_OP_IMM:
            return op.imm
    return None


def classify_string(s):
    low = s.lower()
    if any(ign in low for ign in IGNORE_KEYWORDS):
        return "IGNORE"
    if any(kw in low for kw in PROMPT_KEYWORDS):
        return "PROMPT"
    if any(kw in low for kw in FAILURE_KEYWORDS):
        return "FAILURE"
    if any(kw in low for kw in SUCCESS_KEYWORDS):
        return "SUCCESS"
    return None


# -----------------------------------------------
#  String extraction
# -----------------------------------------------

def extract_strings(data, min_len=4):
    results = []
    # ASCII
    current, start = [], 0
    for i in range(len(data)):
        b = data[i]
        if 0x20 <= b < 0x7F:
            if not current: start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append((start, ''.join(current)))
            current = []
    if len(current) >= min_len:
        results.append((start, ''.join(current)))
    # UTF-16LE
    current, start, i = [], 0, 0
    while i + 1 < len(data):
        wc = data[i] | (data[i+1] << 8)
        if 0x20 <= wc < 0x7F:
            if not current: start = i
            current.append(chr(wc))
            i += 2
        else:
            if len(current) >= min_len:
                results.append((start, ''.join(current)))
            current = []
            i += 2
    if len(current) >= min_len:
        results.append((start, ''.join(current)))
    return results


def find_strings(pe, raw_data, verbose=False):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    all_strs = extract_strings(raw_data)
    failures, successes = [], []
    seen = set()
    for offset, val in all_strs:
        if offset in seen: continue
        kind = classify_string(val)
        if kind == "IGNORE" or kind == "PROMPT":
            if verbose: print(f"    [{kind.lower()}] \"{val[:50]}\"")
            continue
        if kind in ("FAILURE", "SUCCESS"):
            rva = offset_to_rva(pe, offset)
            entry = {'offset': offset, 'rva': rva,
                     'va': image_base + rva if rva else 0,
                     'value': val[:120]}
            if kind == "FAILURE": failures.append(entry)
            else: successes.append(entry)
            seen.add(offset)
    return failures, successes


# -----------------------------------------------
#  Code reference finder (with fuzzy matching)
# -----------------------------------------------

def find_code_refs(instructions, target_va, target_rva, is64, fuzz=32):
    """Find instructions referencing target_va.
    Uses three methods:
      1. Exact operand match (immediate/displacement)
      2. RIP-relative effective address calculation
      3. Raw displacement scan (brute-force, like IDA xref)
    Returns list of (index, exact_match_bool)."""
    refs = []
    found_indices = set()

    for i, ins in enumerate(instructions):
        # Method 1+2: operand-based matching
        for op in ins.operands:
            ref_addr = None
            if op.type == x86_const.X86_OP_IMM:
                ref_addr = op.imm
            elif op.type == x86_const.X86_OP_MEM:
                if is64 and op.mem.base == x86_const.X86_REG_RIP:
                    ref_addr = ins.address + ins.size + op.mem.disp
                elif op.mem.disp:
                    ref_addr = op.mem.disp

            if ref_addr is None:
                continue

            if ref_addr == target_va:
                if i not in found_indices:
                    refs.append((i, True))
                    found_indices.add(i)
                break
            elif abs(ref_addr - target_va) <= fuzz:
                if i not in found_indices:
                    refs.append((i, False))
                    found_indices.add(i)
                break
            if ref_addr == target_rva:
                if i not in found_indices:
                    refs.append((i, True))
                    found_indices.add(i)
                break

    # Method 3: raw displacement scan
    # For each instruction, check if any 4-byte window in its bytes,
    # interpreted as a RIP-relative displacement, points to our target.
    # This catches indirect refs that Capstone doesn't expose cleanly.
    if not refs:
        for i, ins in enumerate(instructions):
            raw = ins.bytes
            if len(raw) < 4:
                continue
            # try every 4-byte window in the instruction
            for off in range(len(raw) - 3):
                disp = struct.unpack_from('<i', bytes(raw), off)[0]
                # RIP-relative: effective = ins.address + ins.size + disp
                eff = ins.address + ins.size + disp
                if abs(eff - target_va) <= fuzz:
                    if i not in found_indices:
                        refs.append((i, abs(eff - target_va) == 0))
                        found_indices.add(i)
                    break
                # also check as absolute displacement
                if abs(disp - target_rva) <= fuzz and target_rva > 0x1000:
                    if i not in found_indices:
                        refs.append((i, False))
                        found_indices.add(i)
                    break

    return refs


# -----------------------------------------------
#  Core cracking engine
# -----------------------------------------------

def crack(pe, raw_data, dry_run=False, verbose=False):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    mode = capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = True

    # --- find strings ---
    print("\n[*] Scanning strings...")
    failures, successes = find_strings(pe, raw_data, verbose)
    print(f"[+] {len(failures)} failure string(s):")
    for f in failures:
        print(f"    [FAIL]    0x{f['rva']:X} \"{f['value'][:60]}\"")
    print(f"[+] {len(successes)} success string(s):")
    for s in successes:
        print(f"    [SUCCESS] 0x{s['rva']:X} \"{s['value'][:60]}\"")

    if not successes and not failures:
        print("[!] No interesting strings found.")
        return []

    # --- disassemble ---
    print("\n[*] Disassembling...")
    instructions = []
    for section in pe.sections:
        is_code = bool(section.Characteristics & 0x20000000) or \
                  bool(section.Characteristics & 0x00000020)
        if not is_code: continue
        sec_data = raw_data[section.PointerToRawData:
                            section.PointerToRawData + section.SizeOfRawData]
        base_addr = image_base + section.VirtualAddress
        instrs = list(md.disasm(sec_data, base_addr))
        sec_name = section.Name.decode('ascii', errors='replace').strip('\x00')
        print(f"  [*] {sec_name}: {len(instrs)} instructions")
        instructions.extend(instrs)

    if not instructions:
        print("[!] No code found.")
        return []

    # --- find code references ---
    print("\n[*] Finding code references...")

    succ_refs = []
    for s in successes:
        if s['va'] == 0: continue
        refs = find_code_refs(instructions, s['va'], s['rva'], is64)
        for idx, exact in refs:
            ins = instructions[idx]
            tag = "" if exact else " (fuzzy)"
            print(f"  [SUCC REF]  0x{ins.address:X} "
                  f"({ins.mnemonic} {ins.op_str}){tag} "
                  f"-> \"{s['value'][:40]}\"")
            succ_refs.append((idx, s))

    fail_refs = []
    for f in failures:
        if f['va'] == 0: continue
        refs = find_code_refs(instructions, f['va'], f['rva'], is64)
        for idx, exact in refs:
            ins = instructions[idx]
            tag = "" if exact else " (fuzzy)"
            print(f"  [FAIL REF]  0x{ins.address:X} "
                  f"({ins.mnemonic} {ins.op_str}){tag} "
                  f"-> \"{f['value'][:40]}\"")
            fail_refs.append((idx, f))

    patches = []

    # ==========================================================
    #  STRATEGY 0: Pair failure + success refs by proximity.
    #  The REAL auth gate is where failure and success strings
    #  are referenced in the SAME code area (~150 instructions).
    #  This avoids patching random UI checks.
    # ==========================================================
    pairs = []  # (fail_idx, fail_info, succ_idx, succ_info, score)

    # relevance keywords -- higher score = more likely the real license gate
    LICENSE_FAIL_BOOST = [
        "invalid key", "wrong key", "bad key", "key invalid",
        "invalid license", "license invalid", "license failed",
        "license expired", "activation failed", "trial expired",
        "login failed",
    ]
    LICENSE_SUCC_BOOST = [
        "welcome", "success", "activated", "registered",
        "licensed", "unlocked", "full version", "pro version",
    ]
    # strings that are app-specific, NOT about the license
    APP_SPECIFIC_PENALTY = [
        "riot", "client", "server", "proxy", "http", "connection",
        "socket", "network", "resource", "timeout",
    ]

    def _pair_score(finfo, sinfo, dist):
        """Score a failure/success pair by relevance to license cracking."""
        score = 100.0
        flow = finfo['value'].lower()
        slow = sinfo['value'].lower()

        # boost for license-related failure strings
        for kw in LICENSE_FAIL_BOOST:
            if kw in flow:
                score += 50
                break

        # boost for welcome/success strings
        for kw in LICENSE_SUCC_BOOST:
            if kw in slow:
                score += 50
                break

        # penalty for app-specific noise
        for kw in APP_SPECIFIC_PENALTY:
            if kw in flow: score -= 30
            if kw in slow: score -= 30

        # slight preference for closer pairs
        score -= dist * 0.5

        return score

    if fail_refs and succ_refs:
        print("\n[*] Strategy 0: Pairing nearby failure + success refs...")
        for fi, finfo in fail_refs:
            for si, sinfo in succ_refs:
                dist = abs(fi - si)
                if dist <= 150:
                    sc = _pair_score(finfo, sinfo, dist)
                    pairs.append((fi, finfo, si, sinfo, sc))

        # sort by score DESCENDING (best pair first)
        pairs.sort(key=lambda x: -x[4])
        seen_fails = set()
        unique_pairs = []
        for fi, finfo, si, sinfo, sc in pairs:
            if fi not in seen_fails:
                seen_fails.add(fi)
                unique_pairs.append((fi, finfo, si, sinfo, sc))
        pairs = unique_pairs[:2]  # max 2 best pairs

        if pairs:
            for fi, finfo, si, sinfo, sc in pairs:
                fi_addr = instructions[fi].address
                si_addr = instructions[si].address
                dist = abs(fi - si)
                print(f"  [PAIR] score={sc:.0f} fail=0x{fi_addr:X} "
                      f"\"{finfo['value'][:30]}\" "
                      f"<-> succ=0x{si_addr:X} \"{sinfo['value'][:30]}\" "
                      f"(dist={dist} instrs)")

                # find the JCC between them that gates the fork
                # the gate is typically BEFORE both refs
                earlier_idx = min(fi, si)
                later_idx = max(fi, si)

                # scan backward from the earlier ref for JCC
                for j in range(earlier_idx - 1, max(earlier_idx - 60, -1), -1):
                    ins = instructions[j]
                    if ins.id in _JCC_IDS:
                        jcc_target = get_jcc_target(ins)
                        if jcc_target is None: continue
                        fall_through = ins.address + ins.size

                        foff = rva_to_offset(pe, ins.address - image_base)
                        if foff == 0: continue
                        old = bytes(raw_data[foff:foff + ins.size])

                        # determine: does this JCC route to success or failure?
                        fail_addr = instructions[fi].address
                        succ_addr = instructions[si].address

                        # if JCC target is closer to failure -> it jumps to fail
                        # -> NOP it (don't take the failure branch)
                        dist_to_fail = abs(jcc_target - fail_addr)
                        dist_to_succ = abs(jcc_target - succ_addr)
                        dist_ft_fail = abs(fall_through - fail_addr)
                        dist_ft_succ = abs(fall_through - succ_addr)

                        if dist_to_fail < dist_to_succ:
                            # JCC jumps toward failure -> NOP it
                            new = b'\x90' * ins.size
                            strat = "NOP"
                            reason = (f"NOP {ins.mnemonic} at 0x{ins.address:X} "
                                     f"(jumps toward failure \"{finfo['value'][:30]}\")")
                        elif dist_ft_fail < dist_ft_succ:
                            # fall-through goes toward failure -> FORCE the JCC
                            new = _make_uncond_jmp(old, ins.size)
                            strat = "FORCE_JMP"
                            reason = (f"Force {ins.mnemonic} at 0x{ins.address:X} "
                                     f"to always jump to success "
                                     f"\"{sinfo['value'][:30]}\")")
                        else:
                            # can't determine, NOP to be safe
                            new = b'\x90' * ins.size
                            strat = "NOP"
                            reason = (f"NOP {ins.mnemonic} at 0x{ins.address:X} "
                                     f"near auth fork")

                        print(f"  [+] AUTH GATE: {ins.mnemonic} at 0x{ins.address:X} "
                              f"| {strat}")
                        patches.append(Patch(foff, ins.size, old, new, strat, reason))
                        break

                    # also check for CALL -> TEST -> JCC pattern
                    if ins.id in (x86_const.X86_INS_TEST, x86_const.X86_INS_CMP):
                        if j + 1 < len(instructions) and \
                           instructions[j + 1].id in _JCC_IDS:
                            jcc = instructions[j + 1]
                            jcc_target = get_jcc_target(jcc)
                            foff = rva_to_offset(pe, jcc.address - image_base)
                            if foff == 0: continue
                            old = bytes(raw_data[foff:foff + jcc.size])

                            fail_addr = instructions[fi].address
                            succ_addr = instructions[si].address

                            if jcc_target and abs(jcc_target - fail_addr) < \
                               abs(jcc_target - succ_addr):
                                new = b'\x90' * jcc.size
                                strat = "NOP"
                            else:
                                new = _make_uncond_jmp(old, jcc.size)
                                strat = "FORCE_JMP"

                            reason = (f"{strat} {jcc.mnemonic} at 0x{jcc.address:X} "
                                     f"(TEST/CMP->JCC auth gate)")
                            print(f"  [+] AUTH GATE: TEST/CMP -> {jcc.mnemonic} "
                                  f"at 0x{jcc.address:X} | {strat}")
                            patches.append(Patch(foff, jcc.size, old, new, strat, reason))
                            break

    # if Strategy 0 found patches, skip the rest
    if patches:
        # deduplicate by offset
        seen_offsets = set()
        deduped = []
        for p in patches:
            if p.file_offset not in seen_offsets:
                seen_offsets.add(p.file_offset)
                deduped.append(p)
        return deduped

    # ==========================================================
    #  STRATEGY 1: Anchor on SUCCESS ref, work backward
    #  Find the JCC that gates entry to the success block.
    #  Force it to always jump to success.
    # ==========================================================
    if succ_refs:
        print("\n[*] Strategy 1: Anchor on success ref, find gate...")

        for succ_idx, succ_info in succ_refs:
            succ_ins = instructions[succ_idx]
            succ_addr = succ_ins.address

            # find the success block start
            succ_block_addr = succ_addr
            for j in range(succ_idx - 1, max(succ_idx - 50, -1), -1):
                prev = instructions[j]
                if prev.id in _BLOCK_ENDERS:
                    if j + 1 < len(instructions):
                        succ_block_addr = instructions[j + 1].address
                    break

            print(f"  [i] Success block: 0x{succ_block_addr:X} "
                  f"(\"{succ_info['value'][:40]}\")")

            # walk backward from the success block looking for JCCs
            # that either: jump TO this block, or jump OVER this block
            for j in range(succ_idx - 1, max(succ_idx - 100, -1), -1):
                ins = instructions[j]

                # skip past other block boundaries (we left the success block)
                # but keep scanning the function

                if ins.id in _JCC_IDS:
                    jcc_target = get_jcc_target(ins)
                    if jcc_target is None: continue
                    fall_through = ins.address + ins.size

                    # Case A: JCC target IS the success block
                    # -> force this JCC to always jump (unconditional JMP)
                    if jcc_target == succ_block_addr:
                        foff = rva_to_offset(pe, ins.address - image_base)
                        if foff == 0: continue
                        old = bytes(raw_data[foff:foff + ins.size])
                        new = _make_uncond_jmp(old, ins.size)

                        print(f"  [+] GATE FOUND: {ins.mnemonic} at 0x{ins.address:X} "
                              f"jumps TO success block")
                        print(f"      Strategy: FORCE_JMP (always take the success branch)")
                        patches.append(Patch(foff, ins.size, old, new, "FORCE_JMP",
                            f"Force {ins.mnemonic} at 0x{ins.address:X} to always "
                            f"jump to success block 0x{succ_block_addr:X}"))
                        break

                    # Case B: JCC target jumps PAST/OVER the success block
                    # -> the fall-through goes to success, but JCC skips it
                    # -> NOP the JCC so we always fall through to success
                    if jcc_target > succ_addr and fall_through <= succ_block_addr:
                        foff = rva_to_offset(pe, ins.address - image_base)
                        if foff == 0: continue
                        old = bytes(raw_data[foff:foff + ins.size])
                        new = b'\x90' * ins.size

                        print(f"  [+] GATE FOUND: {ins.mnemonic} at 0x{ins.address:X} "
                              f"jumps OVER success block")
                        print(f"      Strategy: NOP (remove the skip, fall through to success)")
                        patches.append(Patch(foff, ins.size, old, new, "NOP",
                            f"NOP {ins.mnemonic} at 0x{ins.address:X} that was "
                            f"skipping success block 0x{succ_block_addr:X}"))
                        break

                    # Case C: JCC fall-through reaches success, target goes elsewhere
                    # -> this is already the "good" path, but check if there's a
                    #    closer JCC that's the real gate
                    if (fall_through >= succ_block_addr and
                        fall_through <= succ_block_addr + 50):
                        # fall-through goes to success area -- this JCC might
                        # be jumping to failure. NOP it.
                        foff = rva_to_offset(pe, ins.address - image_base)
                        if foff == 0: continue
                        old = bytes(raw_data[foff:foff + ins.size])
                        new = b'\x90' * ins.size

                        print(f"  [+] GATE FOUND: {ins.mnemonic} at 0x{ins.address:X} "
                              f"fall-through -> success, taken -> elsewhere")
                        print(f"      Strategy: NOP (ensure we always fall through to success)")
                        patches.append(Patch(foff, ins.size, old, new, "NOP",
                            f"NOP {ins.mnemonic} at 0x{ins.address:X} -- "
                            f"fall-through leads to success 0x{succ_block_addr:X}"))
                        break

    # ==========================================================
    #  STRATEGY 2: JMP from failure ref to success block
    #  Direct redirect: overwrite failure path with JMP to success.
    # ==========================================================
    if fail_refs and succ_refs and not patches:
        print("\n[*] Strategy 2: JMP from failure to success...")

        for fail_idx, fail_info in fail_refs:
            fail_ins = instructions[fail_idx]
            fail_addr = fail_ins.address

            # find failure block start
            fail_block_addr = fail_addr
            for j in range(fail_idx - 1, max(fail_idx - 50, -1), -1):
                prev = instructions[j]
                if prev.id in _BLOCK_ENDERS:
                    if j + 1 < len(instructions):
                        fail_block_addr = instructions[j + 1].address
                    break

            # pick best success target
            best_succ_addr = None
            best_dist = float('inf')
            for si, sinfo in succ_refs:
                sa = instructions[si].address
                # find its block start
                sba = sa
                for j in range(si - 1, max(si - 50, -1), -1):
                    if instructions[j].id in _BLOCK_ENDERS:
                        if j + 1 < len(instructions):
                            sba = instructions[j + 1].address
                        break
                d = abs(sa - fail_addr)
                if d < best_dist:
                    best_dist = d
                    best_succ_addr = sba

            if best_succ_addr:
                patch_addr = fail_block_addr
                patch_foff = rva_to_offset(pe, patch_addr - image_base)
                if patch_foff != 0:
                    rel32 = best_succ_addr - (patch_addr + 5)
                    new = b'\xE9' + struct.pack('<i', rel32)
                    old = bytes(raw_data[patch_foff:patch_foff + 5])

                    print(f"  [+] JMP 0x{patch_addr:X} -> 0x{best_succ_addr:X}")
                    print(f"      Failure: \"{fail_info['value'][:40]}\"")
                    patches.append(Patch(patch_foff, 5, old, new, "JMP_TO_SUCCESS",
                        f"JMP from failure 0x{patch_addr:X} to success "
                        f"0x{best_succ_addr:X}"))
                    break

    # ==========================================================
    #  STRATEGY 3: No refs at all? Scan for CALL->TEST->JCC
    #  patterns near the entry point as a heuristic.
    # ==========================================================
    if not patches:
        print("\n[*] Strategy 3: Scanning for CALL->TEST->JCC validation patterns...")
        ep_va = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

        # find the EP in our instruction list
        ep_idx = None
        for i, ins in enumerate(instructions):
            if ins.address == ep_va:
                ep_idx = i
                break

        if ep_idx is not None:
            # scan first 500 instructions from EP for the pattern
            for i in range(ep_idx, min(ep_idx + 500, len(instructions))):
                ins = instructions[i]
                if ins.id != x86_const.X86_INS_CALL: continue

                # look for TEST/CMP -> JCC within 4 instrs
                for j in range(i + 1, min(i + 5, len(instructions))):
                    chk = instructions[j]
                    if chk.id not in (x86_const.X86_INS_TEST, x86_const.X86_INS_CMP):
                        continue
                    if j + 1 >= len(instructions): continue
                    jcc = instructions[j + 1]
                    if jcc.id not in _JCC_IDS: continue

                    # check if any success/failure string is within 50 instrs
                    has_context = False
                    for k in range(i, min(i + 50, len(instructions))):
                        for sr_idx, sr_info in succ_refs:
                            if sr_idx == k: has_context = True
                        for fr_idx, fr_info in fail_refs:
                            if fr_idx == k: has_context = True
                        if has_context: break

                    if not has_context: break

                    # found a validation pattern with context
                    jcc_target = get_jcc_target(jcc)
                    foff = rva_to_offset(pe, jcc.address - image_base)
                    if foff == 0: break

                    old = bytes(raw_data[foff:foff + jcc.size])
                    # try to determine direction
                    # if we have success ref and JCC target is near it -> force JMP
                    # otherwise NOP it
                    if succ_refs:
                        best_sa = instructions[succ_refs[0][0]].address
                        if jcc_target and abs(jcc_target - best_sa) < 200:
                            new = _make_uncond_jmp(old, jcc.size)
                            strat = "FORCE_JMP"
                            reason = (f"Force {jcc.mnemonic} at 0x{jcc.address:X} "
                                     f"(CALL->TEST->JCC pattern, targets success area)")
                        else:
                            new = b'\x90' * jcc.size
                            strat = "NOP"
                            reason = (f"NOP {jcc.mnemonic} at 0x{jcc.address:X} "
                                     f"(CALL->TEST->JCC validation pattern)")
                    else:
                        new = b'\x90' * jcc.size
                        strat = "NOP"
                        reason = (f"NOP {jcc.mnemonic} at 0x{jcc.address:X} "
                                 f"(CALL->TEST->JCC validation pattern)")

                    print(f"  [+] Validation pattern: CALL 0x{ins.address:X} "
                          f"-> {chk.mnemonic} -> {jcc.mnemonic}")
                    print(f"      Strategy: {strat}")
                    patches.append(Patch(foff, jcc.size, old, new, strat, reason))
                    break
                if patches: break

    # ==========================================================
    #  Context dump: show nearby code for manual analysis
    # ==========================================================
    if verbose or not patches:
        all_refs = succ_refs + fail_refs
        if all_refs:
            print("\n[*] Context dump (nearby code):")
            for refs, label in [(succ_refs, "SUCCESS"), (fail_refs, "FAILURE")]:
                for ref_idx, ref_info in refs:
                    addr = instructions[ref_idx].address
                    print(f"\n  --- {label}: \"{ref_info['value'][:50]}\" ---")
                    start = max(0, ref_idx - 15)
                    end = min(len(instructions), ref_idx + 10)
                    for k in range(start, end):
                        ins = instructions[k]
                        marker = " >>>" if k == ref_idx else "    "
                        foff = rva_to_offset(pe, ins.address - image_base)
                        print(f"  {marker} 0x{ins.address:X} (0x{foff:X})  "
                              f"{ins.mnemonic:8s} {ins.op_str}")
        else:
            # no refs at all — dump raw section around string locations
            print("\n[*] No code refs found. Dumping raw data near target strings "
                  "for manual analysis...")
            for label, slist in [("SUCCESS", successes), ("FAILURE", failures)]:
                for s in slist[:3]:
                    rva = s['rva']
                    va = s['va']
                    print(f"\n  --- {label}: \"{s['value'][:50]}\" (VA=0x{va:X}) ---")
                    # scan ALL instructions for anything with displacement
                    # in the neighborhood (wider ±4096 search)
                    nearby = []
                    for i, ins in enumerate(instructions):
                        raw_bytes = ins.bytes
                        if len(raw_bytes) < 4: continue
                        for off in range(len(raw_bytes) - 3):
                            disp = struct.unpack_from('<i', bytes(raw_bytes), off)[0]
                            eff = ins.address + ins.size + disp
                            if abs(eff - va) <= 4096:
                                nearby.append((i, ins, eff, abs(eff - va)))
                                break
                    nearby.sort(key=lambda x: x[3])
                    if nearby:
                        print(f"  Closest code references (within 4KB):")
                        for idx, ins, eff, dist in nearby[:10]:
                            foff = rva_to_offset(pe, ins.address - image_base)
                            print(f"    0x{ins.address:X} (0x{foff:X})  "
                                  f"{ins.mnemonic:8s} {ins.op_str}  "
                                  f"[eff=0x{eff:X}, dist={dist}]")
                    else:
                        print(f"  No references found within 4KB")

    return patches


def _make_uncond_jmp(old_bytes, size):
    """Convert conditional JMP bytes to unconditional JMP."""
    data = bytearray(old_bytes)
    if size == 2 and 0x70 <= data[0] <= 0x7F:
        # short Jcc -> short JMP (EB)
        data[0] = 0xEB
        return bytes(data)
    elif size == 6 and data[0] == 0x0F and 0x80 <= data[1] <= 0x8F:
        # long Jcc (0F 8x) -> near JMP (E9) + NOP
        disp = struct.unpack_from('<i', data, 2)[0]
        disp += 1  # 6->5 byte compensation
        result = bytearray(6)
        result[0] = 0xE9
        struct.pack_into('<i', result, 1, disp)
        result[5] = 0x90
        return bytes(result)
    else:
        return b'\x90' * size  # fallback: NOP


# -----------------------------------------------
#  Apply patches
# -----------------------------------------------

def apply_patches(raw_data, patches, dry_run=False):
    print(f"\n[*] {'DRY RUN' if dry_run else 'Applying'} {len(patches)} patch(es)...\n")
    applied = 0
    for p in patches:
        if p.file_offset + p.size > len(raw_data):
            print(f"  [!] Bad offset 0x{p.file_offset:X}")
            continue
        print(f"  [{p.strategy}] offset 0x{p.file_offset:X} ({p.size}B)")
        print(f"    before: {hexdump(p.old_bytes)}")
        print(f"    after:  {hexdump(p.new_bytes)}")
        print(f"    reason: {p.reason}")
        print()
        if not dry_run:
            raw_data[p.file_offset:p.file_offset + p.size] = p.new_bytes
        applied += 1
    return applied


def fix_checksum(raw_data):
    tmp = pefile.PE(data=bytes(raw_data))
    tmp.OPTIONAL_HEADER.CheckSum = tmp.generate_checksum()
    off = tmp.OPTIONAL_HEADER.get_file_offset() + 0x40
    struct.pack_into('<I', raw_data, off, tmp.OPTIONAL_HEADER.CheckSum)


def save_log(patches, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"AutoCrack Patch Log -- {datetime.now()}\n")
        f.write("=" * 55 + "\n\n")
        for p in patches:
            f.write(f"Strategy:  {p.strategy}\n")
            f.write(f"Offset:    0x{p.file_offset:X}\n")
            f.write(f"Size:      {p.size} bytes\n")
            f.write(f"Before:    {hexdump(p.old_bytes)}\n")
            f.write(f"After:     {hexdump(p.new_bytes)}\n")
            f.write(f"Reason:    {p.reason}\n")
            f.write("---\n")
    print(f"[*] Log: {path}")


def scan_imports(pe):
    bad = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "GetTickCount", "GetTickCount64",
        "QueryPerformanceCounter", "OutputDebugStringA", "OutputDebugStringW",
        "InternetOpenA", "InternetOpenW", "WinHttpOpen",
        "RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW",
        "CryptHashData", "CryptProtectData", "CryptUnprotectData",
    }
    hits = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'): return hits
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('ascii', errors='replace')
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode('ascii', errors='replace')
                if name in bad:
                    hits.append(f"{dll}!{name}")
    return hits


# -----------------------------------------------
#  Main
# -----------------------------------------------

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="AutoCrack v5.0")
    parser.add_argument("target", help="Target PE executable")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not os.path.isfile(args.target):
        print(f"[!] Not found: {args.target}")
        return 1

    print(f"[*] Loading {args.target}...")
    try:
        pe = pefile.PE(args.target)
    except pefile.PEFormatError as e:
        print(f"[!] PE error: {e}")
        return 1

    with open(args.target, 'rb') as f:
        raw = bytearray(f.read())

    is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    print(f"[+] {'PE32+' if is64 else 'PE32'} | "
          f"ImageBase 0x{pe.OPTIONAL_HEADER.ImageBase:X} | "
          f"{len(pe.sections)} sections | "
          f"EP 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")

    sus = scan_imports(pe)
    if sus:
        print(f"\n[*] Suspicious imports:")
        for s in sus: print(f"    [!] {s}")

    patches = crack(pe, raw, dry_run=args.dry_run, verbose=args.verbose)

    if not patches:
        print("\n[!] No patches generated. Use --verbose for code context dump.")
        return 0

    n = apply_patches(raw, patches, dry_run=args.dry_run)
    print(f"[+] {n} patch(es) {'identified' if args.dry_run else 'applied'}")

    if not args.dry_run:
        print("[*] Fixing checksum...")
        try: fix_checksum(raw)
        except Exception as e: print(f"  [!] {e}")

        base, ext = os.path.splitext(args.target)
        out = f"{base}_cracked{ext}"
        with open(out, 'wb') as f: f.write(raw)
        print(f"\n[+] Saved: {out}")
        save_log(patches, out + ".log")

    print("\n[*] Done.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
