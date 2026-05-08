import sys

# The exact flash boundary where the Application must start
BOOTLOADER_TARGET_SIZE = 0x4000  # 16 KB
PAD_BYTE = 0xFF

def build_firmware(bootloader_path, app_path, output_path):
    try:
        # 1. Read the raw Bootloader
        with open(bootloader_path, "rb") as f:
            bootloader_data = f.read()

        current_bl_size = len(bootloader_data)

        # Safety Check: Did your bootloader get too big?
        if current_bl_size > BOOTLOADER_TARGET_SIZE:
            print(f"FATAL ERROR: Bootloader size ({current_bl_size} bytes) exceeds the allocated {BOOTLOADER_TARGET_SIZE} bytes!")
            print("You must optimize your bootloader code or increase the flash sector allocation.")
            sys.exit(1)

        # 2. Pad the Bootloader to exactly 16KB
        padding_size = BOOTLOADER_TARGET_SIZE - current_bl_size
        padding = bytes([PAD_BYTE]) * padding_size
        padded_bootloader = bootloader_data + padding

        # 3. Read the Application firmware
        with open(app_path, "rb") as f:
            app_data = f.read()

        # 4. Combine them and write to the output file
        final_firmware = padded_bootloader + app_data
        
        with open(output_path, "wb") as f:
            f.write(final_firmware)

        # Print a nice summary report
        print(f"Success! Firmware merged into '{output_path}'")
        print("-" * 50)
        print(f"Bootloader (Raw):    {current_bl_size} bytes")
        print(f"Padding Added:       {padding_size} bytes (Filled with 0xFF)")
        print(f"Bootloader (Padded): {len(padded_bootloader)} bytes (Exactly 0x4000)")
        print(f"Application Size:    {len(app_data)} bytes")
        print("-" * 50)
        print(f"Total Flashed Size:  {len(final_firmware)} bytes")

    except FileNotFoundError as e:
        print(f"Error: Could not find file. {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Expect 3 arguments: bootloader.bin, app.bin, output.bin
    if len(sys.argv) == 4:
        build_firmware(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("Usage: python build_full_firmware.py <bootloader.bin> <app.bin> <output.bin>")
        sys.exit(1)
