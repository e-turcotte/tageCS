#!/usr/bin/env python3
import argparse
import csv
import sys
import os
from pathlib import Path

def parse_csv(csv_path: str) -> dict[int, int]:
    """Return {offset: byte} from the CSV using 'nop_pc' and 'prefix_byte' columns."""
    path = Path(csv_path)
    if not path.is_file():
        sys.exit(f"[ERROR] CSV file not found: {csv_path}")

    entries: dict[int, int] = {}

    with path.open(newline="") as fh:
        # Read a sample to detect dialect (comma, tab, semicolon)
        sample = fh.read(2048)
        fh.seek(0)
        try:
            sniffer = csv.Sniffer()
            dialect = sniffer.sniff(sample, delimiters=",\t;")
            has_header = sniffer.has_header(sample)
        except csv.Error:
            dialect = csv.excel
            has_header = True

        reader = csv.DictReader(fh, dialect=dialect)
        # Normalize column names for easier lookup
        reader.fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]

        if "nop_pc" not in reader.fieldnames or "prefix_byte" not in reader.fieldnames:
            sys.exit(
                f"[ERROR] CSV must contain 'nop_pc' and 'prefix_byte' columns.\n"
                f"Found: {reader.fieldnames}"
            )

        for lineno, row in enumerate(reader, start=2):
            pc_str = row.get("nop_pc", "").strip()
            byte_str = row.get("prefix_byte", "").strip()
            
            if not pc_str or not byte_str:
                continue

            try:
                # int(val, 0) handles both hex (0x) and decimal
                pc = int(pc_str, 0)
                byte_val = int(byte_str, 0)
                
                if not (0 <= byte_val <= 0xFF):
                    print(f"[WARN] Byte {byte_val:#x} out of range at row {lineno}; skipping.")
                    continue
                
                entries[pc] = byte_val
            except ValueError:
                print(f"[WARN] Skipping malformed row {lineno}: nop_pc={pc_str!r}, prefix_byte={byte_str!r}")
                continue

    if not entries:
        sys.exit("[ERROR] No valid entries found in CSV.")

    print(f"[INFO] Loaded {len(entries)} patch entries from {csv_path}")
    return entries

def main():
    parser = argparse.ArgumentParser(description="Patch a binary file using offset/byte pairs from a CSV.")
    parser.add_argument("binary_file", help="The executable or binary file to patch.")
    parser.add_argument("csv_file", help="CSV with 'nop_pc' and 'prefix_byte' columns.")
    parser.add_argument("--output", "-o", help="Output file path (default: <bin>.patched)")
    parser.add_argument("--inplace", "-i", action="store_true", help="Overwrite the original file.")
    
    args = parser.parse_args()

    bin_path = Path(args.binary_file)
    if not bin_path.is_file():
        sys.exit(f"[ERROR] Binary file not found: {args.binary_file}")

    # Determine output path
    if args.inplace:
        out_path = bin_path
    elif args.output:
        out_path = Path(args.output)
    else:
        out_path = bin_path.with_suffix(bin_path.suffix + ".patched")

    # 1. Parse CSV
    entries = parse_csv(args.csv_file)

    # 2. Read Binary
    with open(bin_path, "rb") as f:
        data = bytearray(f.read())

    print(f"[INFO] Processing binary: {bin_path} ({len(data)} bytes)")
    print("-" * 60)

    matched_count = 0
    # 3. Apply Patches with Feedback
    for offset, new_byte in entries.items():
        if offset < len(data):
            original_byte = data[offset]
            data[offset] = new_byte
            matched_count += 1
            
            # Detailed console feedback
            print(f"[REPLACE] Offset {offset:#010x} → byte replaced")
            print(f"          original : {original_byte:02X}")
            print(f"          replaced : {new_byte:02X}")
        else:
            print(f"[WARN]    Offset {offset:#010x} is OUT OF BOUNDS (file size: {len(data):#x})")

    # 4. Save Binary
    with open(out_path, "wb") as f:
        f.write(data)
    
    # Ensure it stays executable if it was before
    if not args.inplace:
        os.chmod(out_path, os.stat(bin_path).st_mode)

    print("-" * 60)
    print(f"[DONE] {matched_count}/{len(entries)} patches applied.")
    print(f"[INFO] Output written to: {out_path}")

if __name__ == "__main__":
    main()
