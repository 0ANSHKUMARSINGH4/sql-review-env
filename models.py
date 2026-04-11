from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class SQLReviewAction(BaseModel):
    """Action for the SQL Review environment."""
    review_comment: str = Field(description="Natural language comment identifying SQL issues.")

class SQLReviewObservation(BaseModel):
    """Observation for the SQL Review environment."""
    query: str = Field(description="The SQL query to review.")
    schema_context: Optional[str] = Field(None, description="The database schema associated with the query.")
    feedback_history: List[str] = Field(default_factory=list, description="Previous feedback comments.")
    issues_remaining: int = Field(description="Number of unresolved issues in the current query.")
    done: bool = Field(False, description="Whether the episode is complete.")

class SQLReviewReward(BaseModel):
    """Reward for the SQL Review environment."""
    value: float = Field(0.0, description="The reward value, usually between 0.0 and 1.0.")
