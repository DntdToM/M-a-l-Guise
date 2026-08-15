from search.mcts import MCTS
from search.state import SearchState, EnvStateSnapshot
from detector.interface import DetectorInterface
from actions.cfg_nop_actions import CfgNopActions
import logging

logger = logging.getLogger(__name__)

class MalGuiseAgent:
    def __init__(
        self,
        cfg_nop: CfgNopActions,
        detector: DetectorInterface,
        c_budget: int = 40,
        max_length: int = 6,
        time_budget: float = None,
    ):
        self.cfg_nop = cfg_nop
        self.detector = detector
        self.c_budget = c_budget
        self.max_length = max_length
        self.threshold = 0.5
        self.mcts = MCTS(
            cfg_nop=self.cfg_nop,
            detector=self.detector,
            c_budget=self.c_budget,
            max_length=self.max_length,
            threshold=self.threshold,
            time_budget=time_budget
        )

    def generate_adversarial(self, initial_pe_bytes: bytes):
        logger.info("Initializing search state from initial PE...")
        
        # Take a snapshot of the initial environment state
        initial_snapshot = EnvStateSnapshot(self.cfg_nop)
        
        root_state = SearchState(
            transformation_sequence=[],
            pe_bytes=initial_pe_bytes,
            env_snapshot=initial_snapshot
        )
        
        logger.info("Starting MCTS Search...")
        best_sequence, adv_bytes, search_info = self.mcts.search(root_state)
        
        return best_sequence, adv_bytes, search_info
