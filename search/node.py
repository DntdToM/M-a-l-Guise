import math
import uuid

class MCTSNode:
    def __init__(self, state, parent=None, action=None):
        """
        Args:
            state (SearchState): The state of the environment.
            parent (MCTSNode): The parent node in the MCTS tree.
            action (TransformationAction): The action taken to reach this node.
        """
        self.id = str(uuid.uuid4())[:8]
        self.state = state
        self.parent = parent
        self.action = action
        self.children = []
        self.visits = 0
        self.total_value = 0.0

    @property
    def is_fully_expanded(self):
        # We enforce a bound on expansion width to avoid infinite children 
        # from infinite random action space.
        return len(self.children) > 0

    def ucb1(self, c_param=math.sqrt(2)):
        if self.visits == 0:
            return float('inf')
        q_value = self.total_value / self.visits
        return q_value + c_param * math.sqrt(math.log(self.parent.visits) / self.visits)
