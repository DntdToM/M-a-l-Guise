from search.mcts import MCTS
from search.state import SearchState, EnvStateSnapshot
import logging

logger = logging.getLogger(__name__)

class MalGuiseAgent:
    def __init__(self, cfg_nop_action, detector, c_budget=40, max_length=6, time_budget=None):
        self.cfg_nop_action = cfg_nop_action
        self.mcts = MCTS(
            cfg_nop_action,
            detector,
            c_budget=c_budget,
            max_length=max_length,
            time_budget=time_budget,
        )

    def generate_adversarial(self, initial_pe_bytes: bytes):
        logger.info("Initializing search state from initial PE...")
        
        # Take a snapshot of the initial environment state
        initial_snapshot = EnvStateSnapshot(self.cfg_nop_action)
        
        root_state = SearchState(
            transformation_sequence=[],
            pe_bytes=initial_pe_bytes,
            env_snapshot=initial_snapshot
        )
        
        logger.info("Starting MCTS Search...")
        best_sequence, adv_bytes, search_info = self.mcts.search(root_state)
        
        return best_sequence, adv_bytes, search_info
