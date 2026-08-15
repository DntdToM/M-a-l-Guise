import random
from search.state import SearchState, EnvStateSnapshot
from search.action_space import TransformationAction

def apply_transformation(cfg_nop, current_bytes, seed):
    """
    Applies the atomic transformation: #17 (CFG_EDGE_REDIVIDE) followed by #18 (SEMANTIC_NOP_INJECT).
    """
    # Fix the random state for determinism
    state = random.getstate()
    random.seed(seed)
    
    # 1. CFG_EDGE_REDIVIDE (Action 17)
    intermediate_bytes = cfg_nop.cfg_edge_redivide(current_bytes)
    
    # 2. SEMANTIC_NOP_INJECT (Action 18)
    final_bytes = cfg_nop.semantic_nop_inject(intermediate_bytes)
    
    random.setstate(state)
    return final_bytes

def transition(node, cfg_nop):
    """
    Given a node, apply a random transformation to generate a new child state.
    """
    # 1. Restore the environment state from the node's snapshot
    node.state.env_snapshot.restore(cfg_nop)
    
    # 2. Generate random seed for the action
    seed = random.randint(0, 2**32 - 1)
    action = TransformationAction(seed=seed)
    
    # 3. Apply transformation to get new bytes
    new_bytes = apply_transformation(cfg_nop, node.state.pe_bytes, seed)
    
    # 4. Snapshot the new environment state
    new_snapshot = EnvStateSnapshot(cfg_nop)
    
    # 5. Create the new SearchState
    new_sequence = node.state.transformation_sequence + [action]
    new_state = SearchState(new_sequence, new_bytes, new_snapshot)
    
    return new_state, action
