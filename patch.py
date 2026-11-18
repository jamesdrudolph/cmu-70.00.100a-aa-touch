#!/usr/bin/env python3
"""
Mazda Connect (CMU150 NA 70.00.100A) Android Auto Touchscreen & Speed-Lock Patcher.

Takes an extracted CMU rootfs directory, patches the required files:
  1. etc/aap_system_attributes.xml
     - Adds <touch_screen> with AAP_TOUCH_SCREEN_TYPE_CAPACITIVE and <use_internally>FALSE</use_internally>
       so aap_service advertises InputSourceService.TouchScreen without spawning an unfocused reader.
  2. jci/aapa/blmjciaapa.so
     - Hooks HMIEventHandler::Init() to spawn a background reader thread on /dev/input/touchscreen
       that feeds TUI_TouchInput_s events into HMIEventHandler::InputTouchScreen() (which already
       gates on IsAAVideoInFocus() and handles SBN_Video_Mode_Check()).
     - Forces VbsBcmNoSpeedRestrictTouchDisplayWk() to treat NoSpeedRestrict_TouchDisplay = 1.
     - Stubs VehicleDataManager::SendDriveLevel() and SendSpeed() so AAP_SENSOR_DRIVING_STATUS
       and AAP_SENSOR_SPEED do not trigger driving lockouts.

Outputs patched files into ./output/ (preserving relative paths).
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


# ---------------------------------------------------------------------------
# ARMv7 mini-assembler helpers (all addresses in blmjciaapa.so: vaddr == offset)
# ---------------------------------------------------------------------------

def _enc_b(pc: int, target: int, link: bool = False, cond: int = 0xE) -> int:
    delta = target - (pc + 8)
    if delta % 4 != 0:
        raise ValueError(f"Unaligned branch from 0x{pc:08x} to 0x{target:08x}")
    imm24 = (delta >> 2)
    if imm24 < -0x800000 or imm24 > 0x7FFFFF:
        raise ValueError(f"Branch out of range from 0x{pc:08x} to 0x{target:08x}")
    op = 0xB if link else 0xA
    return (cond << 28) | (op << 24) | (imm24 & 0xFFFFFF)


class ArmAsm:
    def __init__(self, base_addr: int):
        self.base_addr = base_addr
        self.words: list[int] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str, str]] = []  # (idx, kind, label)
        self.literals: list[tuple[str, bytes]] = []

    @property
    def pc(self) -> int:
        return self.base_addr + len(self.words) * 4

    def label(self, name: str) -> None:
        self.labels[name] = self.pc

    def emit(self, word: int) -> None:
        self.words.append(word & 0xFFFFFFFF)

    def b(self, label: str, cond: int = 0xE) -> None:
        idx = len(self.words)
        self.words.append(0)
        self.fixups.append((idx, f"b:{cond}", label))

    def bl(self, target_addr: int) -> None:
        self.emit(_enc_b(self.pc, target_addr, link=True))

    def bl_label(self, label: str) -> None:
        idx = len(self.words)
        self.words.append(0)
        self.fixups.append((idx, "bl", label))

    def adr(self, rd: int, label: str) -> None:
        idx = len(self.words)
        self.words.append(0)
        self.fixups.append((idx, f"adr:{rd}", label))

    def add_data(self, label: str, raw: bytes) -> None:
        self.literals.append((label, raw))

    def finalize(self) -> bytes:
        # Append 4-byte aligned literal/string data after code
        for label, raw in self.literals:
            self.label(label)
            padded = raw + b"\x00" * ((4 - len(raw) % 4) % 4)
            for i in range(0, len(padded), 4):
                self.emit(struct.unpack_from("<I", padded, i)[0])

        for idx, kind, label in self.fixups:
            pc = self.base_addr + idx * 4
            target = self.labels[label]
            if kind.startswith("b:"):
                cond = int(kind.split(":")[1])
                self.words[idx] = _enc_b(pc, target, link=False, cond=cond)
            elif kind == "bl":
                self.words[idx] = _enc_b(pc, target, link=True, cond=0xE)
            elif kind.startswith("adr:"):
                rd = int(kind.split(":")[1])
                delta = target - (pc + 8)
                if delta >= 0:
                    if delta <= 0xFF:
                        self.words[idx] = 0xE28F0000 | (rd << 12) | delta
                    elif delta <= 0x3FC and delta % 4 == 0:
                        # add rd, pc, #(delta>>2), ror #30 (rot=0xF -> imm8 * 4)
                        self.words[idx] = 0xE28F0F00 | (rd << 12) | (delta >> 2)
                    else:
                        raise ValueError(f"ADR forward offset too large: {delta}")
                else:
                    neg = -delta
                    if neg <= 0xFF:
                        self.words[idx] = 0xE24F0000 | (rd << 12) | neg
                    elif neg <= 0x3FC and neg % 4 == 0:
                        self.words[idx] = 0xE24F0F00 | (rd << 12) | (neg >> 2)
                    else:
                        raise ValueError(f"ADR backward offset too large: {neg}")
            else:
                raise ValueError(f"Unknown fixup: {kind}")

        return b"".join(struct.pack("<I", w) for w in self.words)


# ---------------------------------------------------------------------------
# Known addresses & signatures for CMU150_NA_70.00.100A blmjciaapa.so
# ---------------------------------------------------------------------------

ADDR_OPEN_PLT = 0x0004FA54
ADDR_READ_PLT = 0x0004F0C4
ADDR_CLOSE_PLT = 0x0004EF98
ADDR_SLEEP_PLT = 0x00050510
ADDR_PTHREAD_CREATE_PLT = 0x00051194

ADDR_AAPPROCK_GETINSTANCE = 0x0005D154
ADDR_AAPPROCK_GET_RACE = 0x00078890
ADDR_AAPPROCK_GET_VM = 0x000788E4
ADDR_VM_IS_AA_VIDEO_FOCUS = 0x000ABD78
ADDR_RACE_SEND_TOUCH = 0x00086BA4
ADDR_AEABI_UIDIV = 0x000C2C8C

ADDR_HMI_INIT_HOOK = 0x000AFCC4

ADDR_VBS_NO_SPEED_MOV = 0x000B95D8
ADDR_SEND_DRIVE_LEVEL = 0x000BD8DC
ADDR_SEND_SPEED = 0x000C0D24
ADDR_START_SEND_SPEED = 0x000C144C
START_SEND_SPEED_SIZE = 856


def build_touch_payload(base_addr: int) -> bytes:
    """
    Assemble start_touch_reader() + touch_reader_thread() at base_addr (StartSendSpeed).
    Follows oem-aa-mod's touch_send.cpp design:
      - Reads Type-B evdev events from /dev/input/filtered-touchscreen0
      - Gates on VideoManager::IsAAVideoInFocus()
      - Scales raw 0..4099 coordinates to 800x480
      - Builds 0x88-byte AAP_TouchEvent and calls RaceAap::SendTouchInput() directly

    Stack layout in touch_reader_thread (0xA0 = 160 bytes):
      sp + 0x00 .. sp + 0x87 : AAP_TouchEvent (0x88 = 136 bytes)
        +0x00: device_type (1)
        +0x04: finger_count (1)
        +0x08: x[0]
        +0x30: y[0]
        +0x58: pointer_id[0]
        +0x80: action (1=DOWN, 2=UP, 3=MOVE)
        +0x84: action_index (0)
      sp + 0x88 .. sp + 0x97 : struct input_event (16 bytes)
        +0x90: uint16_t type
        +0x92: uint16_t code
        +0x94: int32_t  value
    Callee-saved registers:
      r4 = fd
      r5 = prev_id (-1 initially)
      r6 = cur_id (-1 initially)
      r7 = raw_x
      r8 = raw_y
      r9 = active_slot (0 initially)
    """
    a = ArmAsm(base_addr)

    # --- start_touch_reader (tail-called from HMIEventHandler::Init at 0x000afcc4) ---
    a.label("start_touch_reader")
    a.emit(0xE92D401F)  # push {r0, r1, r2, r3, r4, lr} (6 regs = 24B, 8B aligned)
    a.emit(0xE24DD008)  # sub sp, sp, #8 (for pthread_t)
    a.emit(0xE1A0000D)  # mov r0, sp (&tid)
    a.emit(0xE3A01000)  # mov r1, #0 (attr = NULL)
    a.adr(2, "touch_reader_thread")
    a.emit(0xE3A03000)  # mov r3, #0 (arg = NULL)
    a.bl(ADDR_PTHREAD_CREATE_PLT)
    a.emit(0xE28DD008)  # add sp, sp, #8
    a.emit(0xE8BD401F)  # pop {r0, r1, r2, r3, r4, lr}
    a.emit(0xE24BD008)  # sub sp, fp, #8  (original 0x000afcc4)
    a.emit(0xE8BD4810)  # ldmfd sp!, {r4, fp, lr}
    a.emit(0xE12FFF1E)  # bx lr

    # --- void* touch_reader_thread(void*) ---
    a.label("touch_reader_thread")
    a.emit(0xE92D43F0)  # push {r4, r5, r6, r7, r8, r9, lr} (7 regs = 28B)
    a.emit(0xE24DD0A4)  # sub sp, sp, #0xA4 (164B; 28+164=192, 8B aligned)

    a.emit(0xE3E05000)  # mvn r5, #0  (prev_id = -1)
    a.emit(0xE3E06000)  # mvn r6, #0  (cur_id = -1)
    a.emit(0xE3A07000)  # mov r7, #0  (raw_x = 0)
    a.emit(0xE3A08000)  # mov r8, #0  (raw_y = 0)
    a.emit(0xE3A09000)  # mov r9, #0  (active_slot = 0)

    a.label("open_loop")
    a.adr(0, "dev_path_ts")   # r0 = "/dev/input/filtered-touchscreen0"
    a.emit(0xE3A01000)        # mov r1, #0 (O_RDONLY)
    a.bl(ADDR_OPEN_PLT)
    a.emit(0xE3500000)        # cmp r0, #0
    a.b("open_ok", cond=0xA)  # bge open_ok
    a.emit(0xE3A00001)        # mov r0, #1
    a.bl(ADDR_SLEEP_PLT)
    a.b("open_loop")

    a.label("open_ok")
    a.emit(0xE1A04000)        # mov r4, r0 (fd)

    a.label("read_loop")
    a.emit(0xE1A00004)        # mov r0, r4 (fd)
    a.emit(0xE28D1088)        # add r1, sp, #0x88 (&ev)
    a.emit(0xE3A02010)        # mov r2, #16
    a.bl(ADDR_READ_PLT)
    a.emit(0xE3500010)        # cmp r0, #16
    a.b("got_event", cond=0x0)  # beq got_event
    a.emit(0xE3500000)        # cmp r0, #0
    a.b("read_loop", cond=0xC)  # bgt read_loop
    a.emit(0xE1A00004)        # mov r0, r4
    a.bl(ADDR_CLOSE_PLT)
    a.emit(0xE3A00001)        # mov r0, #1
    a.bl(ADDR_SLEEP_PLT)
    a.b("open_loop")

    a.label("got_event")
    # r0 = ev.type (sp+0x90), r1 = ev.code (sp+0x92), r2 = ev.value (sp+0x94)
    a.emit(0xE1DD09B0)        # ldrh r0, [sp, #0x90] (0x90 -> imm4H=9, imm4L=0)
    a.emit(0xE1DD19B2)        # ldrh r1, [sp, #0x92] (0x92 -> imm4H=9, imm4L=2)
    a.emit(0xE59D2094)        # ldr r2, [sp, #0x94]

    # EV_ABS (3)?
    a.emit(0xE3500003)        # cmp r0, #3
    a.b("check_syn", cond=0x1)  # bne check_syn

    # ABS_MT_SLOT (0x2f)?
    a.emit(0xE351002F)        # cmp r1, #0x2f
    a.b("not_slot", cond=0x1)
    a.emit(0xE1A09002)        # mov r9, r2 (active_slot = ev.value)
    a.b("read_loop")

    a.label("not_slot")
    # Track slot 0 only (ignore multi-finger slots > 0)
    a.emit(0xE3590000)        # cmp r9, #0
    a.b("read_loop", cond=0x1)  # bne read_loop

    a.emit(0xE3510039)        # cmp r1, #0x39 (ABS_MT_TRACKING_ID)
    a.b("not_tid", cond=0x1)
    a.emit(0xE1A06002)        # mov r6, r2 (cur_id = ev.value)
    a.b("read_loop")

    a.label("not_tid")
    a.emit(0xE3510035)        # cmp r1, #0x35 (ABS_MT_POSITION_X)
    a.emit(0x01A07002)        # moveq r7, r2
    a.b("read_loop", cond=0x0)
    a.emit(0xE3510036)        # cmp r1, #0x36 (ABS_MT_POSITION_Y)
    a.emit(0x01A08002)        # moveq r8, r2
    a.b("read_loop")

    # EV_SYN (0) && SYN_REPORT (0)?
    a.label("check_syn")
    a.emit(0xE3500000)        # cmp r0, #0
    a.b("read_loop", cond=0x1)
    a.emit(0xE3510000)        # cmp r1, #0
    a.b("read_loop", cond=0x1)

    # Determine action from prev_id (r5) and cur_id (r6):
    #   prev < 0 && cur >= 0 -> action = 1 (DOWN)
    #   prev >= 0 && cur < 0 -> action = 2 (UP)
    #   prev >= 0 && cur >= 0 -> action = 3 (MOVE)
    #   prev < 0 && cur < 0  -> skip
    a.emit(0xE3550000)        # cmp r5, #0
    a.b("prev_ge0", cond=0xA)  # bge prev_ge0
    a.emit(0xE3560000)        # cmp r6, #0
    a.b("read_loop", cond=0xB)  # blt read_loop (both < 0)
    a.emit(0xE3A0A001)        # mov r10, #1 (DOWN)
    a.b("do_send")

    a.label("prev_ge0")
    a.emit(0xE3560000)        # cmp r6, #0
    a.emit(0xB3A0A002)        # movlt r10, #2 (UP)
    a.emit(0xA3A0A003)        # movge r10, #3 (MOVE)

    a.label("do_send")
    # Check AapProc::GetInstance()->GetVideoManager()->IsAAVideoInFocus()
    a.bl(ADDR_AAPPROCK_GETINSTANCE)
    a.emit(0xE3500000)        # cmp r0, #0
    a.b("update_prev", cond=0x0)
    a.emit(0xE1A0B000)        # mov r11, r0 (save aap)
    a.bl(ADDR_AAPPROCK_GET_VM)
    a.emit(0xE3500000)        # cmp r0, #0
    a.b("update_prev", cond=0x0)
    a.bl(ADDR_VM_IS_AA_VIDEO_FOCUS)
    a.emit(0xE3500000)        # cmp r0, #0
    a.b("update_prev", cond=0x0)

    # Zero-init 0x88 bytes at sp+0..sp+0x84
    a.emit(0xE3A00000)        # mov r0, #0
    a.emit(0xE1A0100D)        # mov r1, sp
    a.emit(0xE28D2088)        # add r2, sp, #0x88
    a.label("zero_loop")
    a.emit(0xE4810004)        # str r0, [r1], #4
    a.emit(0xE1510002)        # cmp r1, r2
    a.b("zero_loop", cond=0x3)  # bcc zero_loop

    # device_type = 1 (+0x00), finger_count = 1 (+0x04)
    a.emit(0xE3A00001)        # mov r0, #1
    a.emit(0xE58D0000)        # str r0, [sp, #0x00]
    a.emit(0xE58D0004)        # str r0, [sp, #0x04]

    # x[0] = raw_x * 800 / 4099
    a.emit(0xE3001320)        # movw r1, #800
    a.emit(0xE0000197)        # mul r0, r7, r1
    a.emit(0xE3011003)        # movw r1, #4099 (0x1003)
    a.bl(ADDR_AEABI_UIDIV)
    a.emit(0xE58D0008)        # str r0, [sp, #0x08]

    # y[0] = raw_y * 480 / 4099
    a.emit(0xE30011E0)        # movw r1, #480 (0x1e0)
    a.emit(0xE0000198)        # mul r0, r8, r1
    a.emit(0xE3011003)        # movw r1, #4099 (0x1003)
    a.bl(ADDR_AEABI_UIDIV)
    a.emit(0xE58D0030)        # str r0, [sp, #0x30]

    # pointer_id[0] = (cur_id >= 0) ? cur_id : prev_id (must match DOWN's pointer_id on UP!)
    a.emit(0xE3560000)        # cmp r6, #0
    a.emit(0xA1A00006)        # movge r0, r6
    a.emit(0xB1A00005)        # movlt r0, r5
    a.emit(0xE58D0058)        # str r0, [sp, #0x58]

    # action (+0x80) = r10
    a.emit(0xE58DA080)        # str r10, [sp, #0x80]

    # Call AapProc::GetRaceAap(aap)->SendTouchInput(&evt)
    a.emit(0xE1A0000B)        # mov r0, r11
    a.bl(ADDR_AAPPROCK_GET_RACE)
    a.emit(0xE3500000)        # cmp r0, #0
    a.b("update_prev", cond=0x0)
    a.emit(0xE1A0100D)        # mov r1, sp
    a.bl(ADDR_RACE_SEND_TOUCH)

    a.label("update_prev")
    a.emit(0xE1A05006)        # mov r5, r6 (prev_id = cur_id)
    a.b("read_loop")

    a.add_data("dev_path_ts", b"/dev/input/filtered-touchscreen0\x00")
    payload = a.finalize()
    if len(payload) > START_SEND_SPEED_SIZE:
        raise RuntimeError(f"Payload ({len(payload)} bytes) exceeds StartSendSpeed ({START_SEND_SPEED_SIZE} bytes)")
    return payload


def patch_xml(src_xml: Path, dst_xml: Path) -> None:
    text = src_xml.read_text(encoding="utf-8")
    root = ET.fromstring(text)
    input_devices = root.find("./head_unit/input_devices")
    if input_devices is None:
        raise RuntimeError(f"Missing <head_unit><input_devices> in {src_xml}")

    if input_devices.find("touch_screen") is not None:
        print(f"[XML] <touch_screen> already present in {src_xml}; copying as-is.")
        dst_xml.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_xml, dst_xml)
        return

    marker = "<input_devices>"
    idx = text.find(marker)
    if idx == -1:
        raise RuntimeError(f"Could not locate {marker} in {src_xml}")

    insert_pos = idx + len(marker)
    snippet = (
        "\n            <touch_screen>\n"
        "                <use_internally>TRUE</use_internally>\n"
        "                <path>/dev/input/filtered-touchscreen0</path>\n"
        "                <type>AAP_TOUCH_SCREEN_TYPE_CAPACITIVE</type>\n"
        "            </touch_screen>"
    )
    patched = text[:insert_pos] + snippet + text[insert_pos:]
    # Validate resulting XML
    ET.fromstring(patched)

    dst_xml.parent.mkdir(parents=True, exist_ok=True)
    dst_xml.write_text(patched, encoding="utf-8")
    print(f"[XML] Patched {dst_xml}")


def patch_blmjciaapa(src_so: Path, dst_so: Path) -> None:
    buf = bytearray(src_so.read_bytes())

    # Verify expected original instructions before patching
    checks = [
        (ADDR_HMI_INIT_HOOK, 0xE24BD008, "HMIEventHandler::Init epilogue"),
        (ADDR_VBS_NO_SPEED_MOV, 0xE1A03001, "VbsBcmNoSpeedRestrictTouchDisplayWk"),
        (ADDR_SEND_DRIVE_LEVEL, 0xE92D4810, "VehicleDataManager::SendDriveLevel"),
        (ADDR_SEND_SPEED, 0xE92D4810, "VehicleDataManager::SendSpeed"),
        (ADDR_START_SEND_SPEED, 0xE92D4810, "VehicleDataManager::StartSendSpeed"),
    ]
    for addr, expected, name in checks:
        actual = struct.unpack_from("<I", buf, addr)[0]
        if actual != expected:
            raise RuntimeError(
                f"Signature mismatch at 0x{addr:08x} ({name}): "
                f"expected 0x{expected:08x}, got 0x{actual:08x}"
            )

    # 1. Inject start_touch_reader + touch_reader_thread into StartSendSpeed
    payload = build_touch_payload(ADDR_START_SEND_SPEED)
    buf[ADDR_START_SEND_SPEED : ADDR_START_SEND_SPEED + len(payload)] = payload
    # Pad remainder with NOPs
    for off in range(ADDR_START_SEND_SPEED + len(payload), ADDR_START_SEND_SPEED + START_SEND_SPEED_SIZE, 4):
        struct.pack_into("<I", buf, off, 0xE1A00000)

    # 2. Hook HMIEventHandler::Init epilogue -> b start_touch_reader
    struct.pack_into("<I", buf, ADDR_HMI_INIT_HOOK, _enc_b(ADDR_HMI_INIT_HOOK, ADDR_START_SEND_SPEED, link=False))

    # 3. Force VbsBcmNoSpeedRestrictTouchDisplayWk() -> noSpeedRestrict = 1 (mov r3, #1)
    struct.pack_into("<I", buf, ADDR_VBS_NO_SPEED_MOV, 0xE3A03001)

    # 4. Stub SendDriveLevel() and SendSpeed() -> mov r0, #0; bx lr
    for stub_addr in (ADDR_SEND_DRIVE_LEVEL, ADDR_SEND_SPEED):
        struct.pack_into("<II", buf, stub_addr, 0xE3A00000, 0xE12FFF1E)

    dst_so.parent.mkdir(parents=True, exist_ok=True)
    dst_so.write_bytes(buf)
    print(f"[ELF] Patched {dst_so} (injected {len(payload)} bytes at 0x{ADDR_START_SEND_SPEED:08x})")


def patch_libjcimod_bcm(src_so: Path, dst_so: Path) -> None:
    buf = bytearray(src_so.read_bytes())

    # VBS_BCM_Send_NoSpeedRestrict_TouchDisplay (0x000063b8):
    #   0x000063c0: e1a02000 (mov r2, r0) -> e3a02000 (mov r2, #0)
    #   0x000063c8: e5c30044 (strb r0, [r3, #0x44]) -> e5c32044 (strb r2, [r3, #0x44])
    checks = [
        (0x000063C0, 0xE1A02000, "VBS_BCM_Send_NoSpeedRestrict_TouchDisplay mov r2, r0"),
        (0x000063C8, 0xE5C30044, "VBS_BCM_Send_NoSpeedRestrict_TouchDisplay strb r0, [r3, #0x44]"),
    ]
    for addr, expected, name in checks:
        actual = struct.unpack_from("<I", buf, addr)[0]
        if actual != expected:
            raise RuntimeError(
                f"Signature mismatch at 0x{addr:08x} ({name}): "
                f"expected 0x{expected:08x}, got 0x{actual:08x}"
            )

    struct.pack_into("<I", buf, 0x000063C0, 0xE3A02000)
    struct.pack_into("<I", buf, 0x000063C8, 0xE5C32044)

    dst_so.parent.mkdir(parents=True, exist_ok=True)
    dst_so.write_bytes(buf)
    print(f"[ELF] Patched {dst_so} (NoSpeedRestrict_TouchDisplay forced to 0 / unrestricted)")


def patch_aap_service(src_bin: Path, dst_bin: Path) -> None:
    buf = bytearray(src_bin.read_bytes())

    # touch_screen_event_reader_thread (vaddr 0x000343dc, file offset 0x0002c3dc):
    # Stub with `mov r0, #0; bx lr` so aap_service still registers InputSourceService.TouchScreen
    # from <use_internally>TRUE</use_internally> without spawning its unfocused evdev reader
    # (which would otherwise double-send touches alongside blmjciaapa.so).
    off = 0x0002C3DC
    expected = 0xE92D4FF0
    actual = struct.unpack_from("<I", buf, off)[0]
    if actual != expected:
        raise RuntimeError(
            f"Signature mismatch at 0x{off:08x} (touch_screen_event_reader_thread): "
            f"expected 0x{expected:08x}, got 0x{actual:08x}"
        )

    struct.pack_into("<II", buf, off, 0xE3A00000, 0xE12FFF1E)

    dst_bin.parent.mkdir(parents=True, exist_ok=True)
    dst_bin.write_bytes(buf)
    print(f"[ELF] Patched {dst_bin} (stubbed touch_screen_event_reader_thread at 0x{off:08x})")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Patch Mazda Connect CMU rootfs for Android Auto touchscreen & speed-lock bypass."
    )
    parser.add_argument(
        "root_dir",
        type=Path,
        help="Path to extracted CMU rootfs directory (containing etc/, jci/, usr/).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "output",
        help="Output directory for patched files (default: ./output).",
    )
    args = parser.parse_args()

    root_dir: Path = args.root_dir.resolve()
    out_dir: Path = args.output.resolve()

    src_xml = root_dir / "etc" / "aap_system_attributes.xml"
    src_so = root_dir / "jci" / "aapa" / "blmjciaapa.so"
    src_bcm = root_dir / "jci" / "vbs" / "modules" / "libjcimod_bcm.so"
    src_aap_svc = root_dir / "usr" / "bin" / "aap_service"

    for p in (src_xml, src_so, src_bcm, src_aap_svc):
        if not p.is_file():
            print(f"Error: required file not found: {p}", file=sys.stderr)
            return 1

    patch_xml(src_xml, out_dir / "etc" / "aap_system_attributes.xml")
    patch_blmjciaapa(src_so, out_dir / "jci" / "aapa" / "blmjciaapa.so")
    patch_libjcimod_bcm(src_bcm, out_dir / "jci" / "vbs" / "modules" / "libjcimod_bcm.so")
    patch_aap_service(src_aap_svc, out_dir / "usr" / "bin" / "aap_service")
    print(f"Done. Patched files written to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
