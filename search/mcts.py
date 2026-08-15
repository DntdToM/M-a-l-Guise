import random
import logging
import math
import time
from search.node import MCTSNode
from search.transition import transition

logger = logging.getLogger(__name__)

class MCTS:
    def __init__(self, cfg_nop, detector, c_budget=40, max_length=6, ucb_c=math.sqrt(2), time_budget=None):
        self.cfg_nop = cfg_nop
        self.detector = detector
        self.c_budget = c_budget
        self.max_length = max_length
        self.ucb_c = ucb_c
        self.time_budget = time_budget
        self.baseline_prob = 1.0
        self.best_prob = None
        self.search_status = "not_started"
        self.simulations = 0

    def search(self, root_state):
        """
        Implements Algorithm 1 (MCTS-Guided Searching Algorithm) from MalGuise.
        """
        started_at = time.monotonic()
        deadline = None if self.time_budget is None else started_at + float(self.time_budget)

        def time_exceeded():
            return deadline is not None and time.monotonic() >= deadline

        def finish(status, state, prob):
            self.search_status = status
            self.best_prob = prob
            elapsed = time.monotonic() - started_at
            info = {
                "status": status,
                "baseline_probability": self.baseline_prob,
                "best_probability": prob,
                "simulations": self.simulations,
                "elapsed_seconds": elapsed,
                "time_budget_seconds": self.time_budget,
            }
            if state is None:
                return [], None, info
            return state.transformation_sequence, state.pe_bytes, info

        # Phase 3: Evaluate baseline probability g(z)
        logger.info("Evaluating baseline probability g(z) for root state...")
        root_result = self.detector.predict(root_state.pe_bytes)
        self.baseline_prob = getattr(root_result, 'malware_prob', 1.0)
        logger.info(f"Baseline probability g(z) = {self.baseline_prob:.4f}")

        v = MCTSNode(state=root_state)
        best_state = None
        best_prob = float("inf")

        if time_exceeded():
            logger.warning("Time budget exhausted after baseline evaluation; no transformed candidate generated.")
            return finish("time_budget_no_candidate", best_state, None)
        
        # We process depth step-by-step
        for i in range(1, self.max_length + 1):
            if time_exceeded():
                logger.info(f"Time budget reached before depth={i}. Returning best candidate.")
                return finish("time_budget", best_state, None if best_state is None else best_prob)

            logger.info(f"MCTS Depth {i}/{self.max_length}")
            
            for j in range(1, self.c_budget + 1):
                if time_exceeded():
                    logger.info(
                        f"Time budget reached at depth={i}, iteration={j}. "
                        "Returning best candidate."
                    )
                    return finish("time_budget", best_state, None if best_state is None else best_prob)

                # Selection vs Expansion (limit unbounded branching)
                if v.children and random.random() < 0.5:
                    v_selected = self.selection(v)
                else:
                    v_selected = self.expansion(v)
                
                # Simulation
                reward, result = self.simulation(v_selected, i, j)
                self.simulations += 1
                
                # Backpropagation
                self.backpropagation(v_selected, reward)

                malware_prob = getattr(result, 'malware_prob', 1.0)
                if best_state is None or malware_prob < best_prob:
                    best_prob = malware_prob
                    best_state = v_selected.state
                    logger.info(
                        f"New best candidate: prob={best_prob:.4f}, "
                        f"sequence_len={len(best_state.transformation_sequence)}"
                    )

                if not getattr(result, 'is_malware', True):
                    logger.info(
                        f"Early stop: evasive candidate found at depth={i}, "
                        f"iteration={j}, prob={malware_prob:.4f}, "
                        f"sequence_len={len(v_selected.state.transformation_sequence)}"
                    )
                    return finish("evaded", v_selected.state, malware_prob)
                
            # Select child with highest average reward for the next depth
            if not v.children:
                logger.warning("No children generated during expansion. Stopping search.")
                break
                
            v_node = max(v.children, key=lambda c: c.total_value / c.visits if c.visits > 0 else 0)
            v = v_node
            v.parent = None # Cut the tree and move down
            
        if best_state is None:
            logger.info("MCTS budget exhausted without a transformed candidate.")
            return finish("budget_exhausted_no_candidate", best_state, None)

        logger.info(f"MCTS budget exhausted. Returning best candidate with prob={best_prob:.4f}.")
        return finish("budget_exhausted", best_state, best_prob)

    def selection(self, node):
        curr = node
        while curr.children:
            curr = max(curr.children, key=lambda c: c.ucb1(self.ucb_c))
            if len(curr.state.transformation_sequence) >= self.max_length:
                break
        return curr

    def expansion(self, node):
        if len(node.state.transformation_sequence) >= self.max_length:
            return node
            
        new_state, action = transition(node, self.cfg_nop)
        child = MCTSNode(state=new_state, parent=node, action=action)
        node.children.append(child)
        return child

    def simulation(self, node, depth, iteration):
        result = self.detector.predict(node.state.pe_bytes)
        
        # Reward formulation based on MalGuise paper and Phase 3 plan
        # R = g(z) - g(x_adv)
        if self.detector.use_probability:
            malware_prob = getattr(result, 'malware_prob', 1.0)
            reward = self.baseline_prob - malware_prob
        else:
            # Fallback if probability is not available
            reward = 1.0 if not result.is_malware else 0.0
            malware_prob = 1.0 if result.is_malware else 0.0
            
        parent_id = node.parent.id if node.parent else "ROOT"
        action_name = node.action.name if node.action else "None"
        
        logger.info(
            f"MCTS-SIM | iteration={iteration} | depth={depth} | node_id={node.id} | parent_node_id={parent_id} | "
            f"action={action_name} | original_probability={self.baseline_prob:.4f} | "
            f"current_probability={malware_prob:.4f} | reward={reward:.4f}"
        )
            
        return reward, result

    def backpropagation(self, node, reward):
        curr = node
        while curr is not None:
            curr.visits += 1
            curr.total_value += reward
            curr = curr.parent
