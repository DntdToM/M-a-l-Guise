import copy

class EnvStateSnapshot:
    def __init__(self, cfg_nop):
        self.call_sites = [dict(site) for site in cfg_nop._call_sites]
        self.is_pe64 = cfg_nop._is_pe64
        self.bridge_registry = [dict(b) for b in cfg_nop._bridge_registry]
        self.total_nop_bytes = cfg_nop._total_nop_bytes_injected

    def restore(self, cfg_nop):
        cfg_nop._call_sites = [dict(site) for site in self.call_sites]
        cfg_nop._is_pe64 = self.is_pe64
        cfg_nop._bridge_registry = [dict(b) for b in self.bridge_registry]
        cfg_nop._total_nop_bytes_injected = self.total_nop_bytes

class SearchState:
    def __init__(self, transformation_sequence, pe_bytes, env_snapshot):
        """
        Lightweight state that holds the byte array and the internal tracking variables
        of cfg_nop_actions.py without needing to re-run angr analysis.
        """
        self.transformation_sequence = transformation_sequence
        self.pe_bytes = pe_bytes
        self.env_snapshot = env_snapshot
