"""
Action space definitions for MalGuise MCTS.
"""
class TransformationAction:
    def __init__(self, seed=None, edge_redivide_params=None, semantic_nop_params=None):
        self.seed = seed
        self.edge_redivide_params = edge_redivide_params
        self.semantic_nop_params = semantic_nop_params
        
    @property
    def name(self):
        parts = []
        if self.edge_redivide_params:
            parts.append("EdgeRedivide")
        if self.semantic_nop_params:
            parts.append("SemanticNop")
        if not parts:
            parts.append("None")
        return f"{'_'.join(parts)}(seed={self.seed})"

