from dataclasses import dataclass
from typing import List, Dict, Optional, Literal

@dataclass
class PromptInput:
    mode: Literal["chat", "completion"]
    messages: Optional[List[Dict[str, str]]] = None
    system_prompt: Optional[str] = None
    completion_prompt: Optional[str] = None