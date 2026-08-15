from __future__ import annotations
from typing import List, Dict, Any, Optional
import re
from models import SQLReviewAction, SQLReviewObservation, SQLReviewReward
from rubrics import SQLReviewRubric

class SQLReviewEnv:
    """Core environment for reviewing SQL queries."""
    
    def __init__(self):
        self.scenarios = {
            "easy-sql-review": {
                "query": "SELECT * FROM users WHERE id = '\" + user_id + \"'",
                "schema": "Table: users (id INT, name VARCHAR, email VARCHAR)",
                "issues": ["sql_injection"],
                "difficulty": "easy"
            },
            "medium-sql-review": {
                "query": "-- Pattern: for order in orders: fetch items\nSELECT * FROM order_items WHERE order_id = ?",
                "schema": "Table: orders (id INT, date DATE); Table: order_items (id INT, order_id INT, sku VARCHAR)",
                "issues": ["n_plus_one"],
                "difficulty": "medium"
            },
            "hard-sql-review": {
                "query": "SELECT * FROM orders o JOIN line_items l ON o.id = l.order_id WHERE o.customer_id = '\" + customer_id + \"' AND l.amount > 100",
                "schema": "Table: orders (id INT, customer_id INT); Table: line_items (id INT, order_id INT, amount DECIMAL)",
                "issues": ["sql_injection", "missing_index", "inefficient_join"],
                "difficulty": "hard"
            },
            "security-extreme": {
                "query": "EXEC('SELECT ' + @cols + ' FROM ' + @table + ' WHERE id = ' + @id + ' ORDER BY ' + @sort)",
                "schema": "Context: Dynamic SQL execution in a stored procedure.",
                "issues": ["sql_injection"],
                "difficulty": "hard"
            },
            "performance-optimization": {
                "query": "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE status = 'pending') AND (SELECT COUNT(*) FROM logs WHERE logs.user_id = users.id) > 0",
                "schema": "Table: users (id); Table: orders (user_id, status); Table: logs (user_id)",
                "issues": ["inefficient_join", "unnecessary_columns"],
                "difficulty": "medium"
            }
        }
        self.current_task_id = "easy-sql-review"
        self.done = False
        self.rubric = SQLReviewRubric()
        from scenarios.generator import ScenarioGenerator
        self.generator = ScenarioGenerator()

    def reset(
        self,
        task: str = "easy-sql-review",
        seed: Optional[int] = None,
        dialect: str = "postgres",
        difficulty: str = "medium",
    ) -> SQLReviewObservation:
        """Reset the environment to a specific task or generate a dynamic scenario."""
        if task.startswith("generated") or seed is not None:
            actual_seed = seed if seed is not None else 12345
            if ":" in task:
                try:
                    actual_seed = int(task.split(":")[1])
                except ValueError:
                    pass
            
            gen_scenario = self.generator.generate(
                seed=actual_seed,
                dialect=dialect,
                difficulty=difficulty,
            )
            task_id = gen_scenario.scenario_id
            self.scenarios[task_id] = {
                "query": gen_scenario.query,
                "schema": gen_scenario.schema,
                "issues": [gt.issue for gt in gen_scenario.target_issues],
                "difficulty": gen_scenario.difficulty,
                "dialect": gen_scenario.dialect,
            }
            self.current_task_id = task_id
        elif task in self.scenarios:
            self.current_task_id = task
        else:
            self.current_task_id = "easy-sql-review"
            
        self.feedback_history = []
        self.steps = 0
        self.done = False
        
        # Initialize rubric with expected issues
        self.rubric.reset()
        self.rubric.set_expected(self.scenarios[self.current_task_id]["issues"])
        
        return self.state()

    def state(self) -> SQLReviewObservation:
        """Return the current state."""
        scenario = self.scenarios[self.current_task_id]
        remaining = len(scenario["issues"]) - len(self.rubric.found_issues)
        
        return SQLReviewObservation(
            query=scenario["query"],
            schema_context=scenario["schema"],
            feedback_history=self.feedback_history,
            issues_remaining=remaining,
            done=self.done
        )

    def step(self, action: SQLReviewAction) -> Dict[str, Any]:
        """Progress the environment based on the agent's action."""
        if self.done:
            return self._result(0.0)

        self.steps += 1
        comment = action.review_comment
        self.feedback_history.append(comment)
        
        # Calculate reward via rubric
        reward_value = self.rubric(action, self.state())
        
        # Scenario status
        scenario = self.scenarios[self.current_task_id]
        all_found = len(self.rubric.found_issues) == len(scenario["issues"])
        
        if all_found or self.steps >= self.max_steps:
            self.done = True
            
        return self._result(reward_value)

    def _result(self, reward_value: float) -> Dict[str, Any]:
        """Format the step result."""
        return {
            "observation": self.state(),
            "reward": SQLReviewReward(value=reward_value),
            "done": self.done,
            "info": {
                "step": self.steps,
                "found_issues": list(self.rubric.found_issues),
                "remaining_issues": self.state().issues_remaining
            }
        }
