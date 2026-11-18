# Mazda Connect Android Auto Touchscreen & Speed-Lock Patcher

Targets **CMU150 NA 70.00.100A**.

## Usage

```bash
python patch.py <path-to-extracted-rootfs>
```

Optional `-o / --output` overrides the output directory (defaults to `./output` inside this folder).

## What It Patches

1. **`etc/aap_system_attributes.xml`**
   - Adds `<touch_screen>` with `<use_internally>TRUE</use_internally>`, `<path>/dev/input/filtered-touchscreen0</path>`, and `<type>AAP_TOUCH_SCREEN_TYPE_CAPACITIVE</type>` under `<head_unit><input_devices>`.
   - Ensures `aap_service` advertises `InputSourceService.TouchScreen` to the connected Android phone.

2. **`usr/bin/aap_service`**
   - Stubs `touch_screen_event_reader_thread` (`0x0002c3dc`) with `mov r0, #0; bx lr` so `aap_service` does not spawn its own unfocused `evdev` reader alongside `blmjciaapa.so` (avoiding duplicate/conflicting touch events and background-touch leakage).

3. **`jci/aapa/blmjciaapa.so`**
   - Hooks `HMIEventHandler::Init()` (`0x000afcc4`) to spawn a background `evdev` reader thread (`touch_reader_thread`, injected into `StartSendSpeed` at `0x000c144c`) on `/dev/input/filtered-touchscreen0`.
   - Gates every frame on `VideoManager::IsAAVideoInFocus()`, scales raw `0..4099` coordinates to `800x480`, builds the `0x88`-byte `AAP_TouchEvent` struct (preserving `pointer_id` across `DOWN`/`MOVE`/`UP`), and dispatches directly via `RaceAap::SendTouchInput()`.
   - Forces `VehicleDataManager::VbsBcmNoSpeedRestrictTouchDisplayWk()` (`0x000b95d8`) to treat `NoSpeedRestrict_TouchDisplay = 1`.
   - Stubs `VehicleDataManager::SendDriveLevel()` (`0x000bd8dc`) and `VehicleDataManager::SendSpeed()` (`0x000c0d24`) so `AAP_SENSOR_DRIVING_STATUS` and `AAP_SENSOR_SPEED` do not trigger driving lockouts or setup dialogs.

4. **`jci/vbs/modules/libjcimod_bcm.so`**
   - Patches `VBS_BCM_Send_NoSpeedRestrict_TouchDisplay()` (`0x000063c0`, `0x000063c8`) so `NoSpeedRestrict_TouchDisplay` always posts `restrict = 0` (unrestricted) on both HMI and Service DBus, keeping `/dev/input/filtered-touchscreen0` active while driving.

## Deployment

Remount `/` read-write on the CMU, back up the original files (e.g. `*.bak`), copy the contents of `output/` into place (using atomic `mv` for `.so`/binary files), `sync`, and reboot:

- `output/etc/aap_system_attributes.xml` → `/etc/aap_system_attributes.xml`
- `output/usr/bin/aap_service` → `/usr/bin/aap_service`
- `output/jci/aapa/blmjciaapa.so` → `/jci/aapa/blmjciaapa.so`
- `output/jci/vbs/modules/libjcimod_bcm.so` → `/jci/vbs/modules/libjcimod_bcm.so`
