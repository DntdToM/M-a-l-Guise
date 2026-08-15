import argparse
import logging
import sys
import os
import angr
import lief

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import hashlib
import shutil
from pathlib import Path
from search.agent import MalGuiseAgent
from detector.magic_adapter import MagicAdapter
from pipeline.reconstruction import AdversarialReconstructor
from actions.cfg_nop_actions import CfgNopActions

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MalGuise")

def _collect_near_call_sites(path: str) -> list[dict]:
    project = angr.Project(
        path,
        auto_load_libs=False,
        load_options={"main_opts": {"base_addr": 0, "force_rebase": True}},
    )
    cfg = project.analyses.CFGFast(cross_references=False, collect_data_references=False, resolve_indirect_jumps=False)

    call_sites: list[dict] = []
    seen_rvas = set()
    for node in cfg.graph.nodes():
        try:
            block = node.block
        except Exception:
            continue
        if block is None:
            continue

        for insn in block.capstone.insns:
            raw = bytes(insn.bytes)
            if insn.mnemonic == "call" and insn.size == 5 and raw[:1] == b"\xE8":
                rva = int(insn.address)
                if rva not in seen_rvas:
                    call_sites.append({"rva": rva, "size": int(insn.size)})
                    seen_rvas.add(rva)
    return call_sites

def main():
    parser = argparse.ArgumentParser(description="MalGuise Framework Pipeline")
    parser.add_argument("--input", type=str, required=True, help="Path to input malicious PE file")
    parser.add_argument("--output", type=str, required=True, help="Path to output adversarial PE file")
    parser.add_argument("--c-budget", type=int, default=40, help="Computation budget C for MCTS (default: 40)")
    parser.add_argument("--max-length", type=int, default=6, help="Maximum length N of transformation sequence (default: 6)")
    parser.add_argument("--detector", type=str, choices=["synthetic", "magic"], default="synthetic", help="Target detector to evaluate against (default: synthetic)")
    parser.add_argument("--magic-dir", type=str, default="detector/MAGIC", help="Path to MAGIC detector directory (used if --detector magic)")
    parser.add_argument("--time-budget", type=float, default=None, help="Soft search time budget in seconds. Returns the best evaluated candidate when reached.")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        logger.error(f"Input file {args.input} does not exist.")
        sys.exit(1)

    logger.info(f"Initializing MalGuise Pipeline on {args.input}")
    
    # 1. Initialize Detector
    if args.detector == "synthetic":
        logger.info("Loading SyntheticDetector (Rugged deterministic oracle)...")
        from detector.synthetic_detector import SyntheticDetector
        detector = SyntheticDetector()
    else:
        logger.info("Loading MAGIC Adapter...")
        detector = MagicAdapter(magic_dir=args.magic_dir)

    # 2. Extract CFG and setup CfgNopActions
    logger.info("Parsing CFG (angr) to find CALL sites...")
    call_sites = _collect_near_call_sites(args.input)
    
    with open(args.input, "rb") as f:
        initial_pe_bytes = f.read()
        
    pe = lief.PE.parse(initial_pe_bytes)
    is_pe64 = pe.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS
    
    cfg_nop_action = CfgNopActions()
    cfg_nop_action._call_sites = call_sites
    cfg_nop_action._is_pe64 = is_pe64
    
    # 3. Run MCTS Search
    logger.info(f"Starting MCTS Search (Initial configuration: C={args.c_budget}, N={args.max_length})...")
    agent = MalGuiseAgent(
        cfg_nop_action=cfg_nop_action,
        detector=detector,
        c_budget=args.c_budget,
        max_length=args.max_length,
        time_budget=args.time_budget
    )
    
    best_sequence, adv_bytes, search_info = agent.generate_adversarial(initial_pe_bytes)
    
    if not best_sequence or not adv_bytes:
        logger.warning("[FAILURE] MCTS could not find any transformed candidate within the budget.")
        sys.exit(1)
        
    # Double check if it actually evaded and preserve artifacts if using MAGIC
    if args.detector == "magic":
        result = detector.predict(adv_bytes, preserve_artifacts=True)
    else:
        result = detector.predict(adv_bytes)
        
    is_malware = getattr(result, 'is_malware', False)
    malware_prob = getattr(result, 'malware_prob', 0.0)
    
    if is_malware:
        logger.warning(
            f"[BEST-EFFORT] Best sequence length {len(best_sequence)} did not evade "
            f"the detector, but reduced/achieved prob={malware_prob:.4f}. Saving candidate."
        )
    else:
        logger.info(f"[SUCCESS] Found evasive sequence of length {len(best_sequence)} with final prob {malware_prob:.4f}.")
    
    # 4. Save Adversarial Malware and CFG Artifact
    logger.info("Reconstructing adversarial malware and saving artifacts...")
    output_path = Path(args.output)
    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    reconstructor = AdversarialReconstructor()
    success = reconstructor.save_adversarial_malware(adv_bytes, str(output_path))
    
    if success:
        logger.info(f"[SUCCESS] Adversarial malware saved to {output_path}")
        
        # Read back to ensure we have the exact saved bytes
        with open(output_path, "rb") as f:
            saved_bytes = f.read()
        saved_sha256 = hashlib.sha256(saved_bytes).hexdigest()
        input_sha256 = hashlib.sha256(initial_pe_bytes).hexdigest()
        
        # Integrity check and CFG preservation
        cfg_source_sha256 = getattr(result, 'cfg_source_sha256', None)
        cfg_path = getattr(result, 'cfg_path', None)
        
        final_cfg_dest = None
        if cfg_source_sha256 and cfg_path:
            if saved_sha256 != cfg_source_sha256:
                logger.error(f"[INTEGRITY ERROR] Saved PE hash ({saved_sha256}) does not match CFG source hash ({cfg_source_sha256}).")
                sys.exit(1)
            
            final_cfg_dest = output_path.with_name(f"{output_path.stem}_final_cfg.json")
            shutil.copy2(cfg_path, final_cfg_dest)
            logger.info(f"Preserved CFG artifact verified and saved to {final_cfg_dest}")
        
        # Save metadata
        result_metadata = {
            "sample_id": output_path.stem.replace("_adv", ""),
            "input_sha256": input_sha256,
            "adv_sha256": saved_sha256,
            "cfg_source_sha256": cfg_source_sha256,
            "baseline_probability": getattr(agent.mcts, 'baseline_prob', 1.0),
            "final_probability": malware_prob,
            "probability_reduction": getattr(agent.mcts, 'baseline_prob', 1.0) - malware_prob,
            "is_malware": is_malware,
            "success": not is_malware,
            "status": "evaded" if not is_malware else "best_effort_not_evaded",
            "search_info": search_info,
            "best_sequence": [action.name for action in best_sequence],
            "num_transformations": len(best_sequence)
        }
        
        result_json_path = output_path.with_name(f"{output_path.stem}_result.json")
        with open(result_json_path, "w") as f:
            json.dump(result_metadata, f, indent=4)
        logger.info(f"Saved execution metadata to {result_json_path}")
        
    else:
        logger.error("[FAILURE] Failed to save the adversarial file.")

        
if __name__ == "__main__":
    main()
