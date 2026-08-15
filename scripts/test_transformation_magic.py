import os
import sys
from pathlib import Path
import lief

# Add MalGuise to Python path so imports work
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from detector.magic_adapter import MagicAdapter
from actions.cfg_nop_actions import CfgNopActions

def main():
    test_pe_path = PROJECT_ROOT / "detector" / "MSACFG" / "Test" / "Zbot" / "002c3a4a12eb9cdc80754e4cddccbc98e5769392.exe"
    if not test_pe_path.exists():
        print(f"Test PE not found: {test_pe_path}")
        return

    print("Loading test PE...")
    with open(test_pe_path, "rb") as f:
        original_bytes = f.read()

    # Rebuild with LIEF to ensure normalization (like MalwareEnv does)
    pe = lief.PE.parse(original_bytes)
    builder = lief.PE.Builder(pe, lief.PE.Builder.config_t())
    builder.build()
    original_bytes = bytes(builder.raw_bytes())

    magic_dir = PROJECT_ROOT / "detector" / "MAGIC"
    adapter = MagicAdapter(str(magic_dir))

    print("--- Getting Initial Probability p1 ---")
    res1 = adapter.predict(original_bytes)
    p1 = res1.malware_prob
    print(f"p1 = {p1}")

    print("\n--- Applying Transformation (SECTION_ADD) ---")
    
    # We will just append a dummy section using lief directly to simulate an action 
    # (since we just want to verify probability change in the pipeline)
    pe = lief.PE.parse(original_bytes)
    section = lief.PE.Section(".magic")
    section.content = [0x55, 0x89, 0xE5, 0x90, 0x90, 0x5D, 0xC3] + [0x90] * 100
    section.characteristics = int(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE) | int(lief.PE.Section.CHARACTERISTICS.MEM_READ) | int(lief.PE.Section.CHARACTERISTICS.CNT_CODE)
    pe.add_section(section)
    
    builder = lief.PE.Builder(pe, lief.PE.Builder.config_t())
    builder.build()
    transformed_bytes = bytes(builder.raw_bytes())

    if transformed_bytes == original_bytes:
        print("Transformation failed or produced identical bytes!")
        return
    else:
        print(f"Transformation success. Original size: {len(original_bytes)}, Transformed size: {len(transformed_bytes)}")

    with open("original.exe", "wb") as f:
        f.write(original_bytes)
    with open("transformed.exe", "wb") as f:
        f.write(transformed_bytes)

    print("\n--- Getting Post-Transformation Probability p2 ---")
    res2 = adapter.predict(transformed_bytes)
    p2 = res2.malware_prob
    print(f"p2 = {p2}")

    delta = p2 - p1
    print(f"\n--- Result ---")
    print(f"p1 = {p1}")
    print(f"p2 = {p2}")
    print(f"Delta = {delta}")

if __name__ == "__main__":
    main()
