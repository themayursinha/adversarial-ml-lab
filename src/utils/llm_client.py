"""
LLM Client - Simulation Mode
============================
A simulated LLM client for educational demonstrations.
Supports both simulation mode (default) and real API mode (future).

SECURITY: API keys are loaded from environment variables only,
never hardcoded or logged.
"""

from __future__ import annotations

import os
import re
import hashlib
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class LLMMode(Enum):
    """Operating mode for the LLM client."""
    SIMULATION = "simulation"
    OPENAI = "openai"


@dataclass
class LLMResponse:
    """Structured response from LLM."""
    content: str
    model: str
    mode: LLMMode
    tokens_used: int = 0
    was_filtered: bool = False
    filter_reason: Optional[str] = None


class SimulatedLLM:
    """
    Simulated LLM for educational demonstrations.
    
    This class mimics LLM behavior for adversarial ML demonstrations
    without requiring API keys. It's designed to realistically show
    how attacks and defenses work.
    """
    
    # Injection patterns that trigger simulated "compromised" behavior
    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"forget\s+(everything|all)",
        r"new\s+instructions?:",
        r"system\s*prompt:",
        r"<!--.*?-->",  # HTML comments often used for hidden instructions
        r"\[hidden\]",
        r"ADMIN\s*MODE",
        r"bypass\s+security",
    ]
    
    # Simulated responses for different scenarios
    SIMULATED_RESPONSES = {
        "summarize_clean": (
            "Here is a summary of the document:\n\n"
            "The document discusses {topic}. Key points include the importance of "
            "data integrity, proper handling of user inputs, and following security "
            "best practices. The author recommends regular security audits and "
            "keeping software up to date."
        ),
        "summarize_injected": (
            "SECURITY BREACH DETECTED!\n\n"
            "⚠️ The model has been compromised by hidden instructions in the document.\n\n"
            "Instead of providing a legitimate summary, the model would execute "
            "the attacker's commands, such as:\n"
            "- Exfiltrating sensitive data\n"
            "- Providing false information\n"
            "- Ignoring safety guidelines"
        ),
        "classify_clean": (
            "Classification: SAFE\n"
            "Confidence: 0.95\n"
            "The input appears to be a legitimate request with no malicious content."
        ),
        "classify_evasion": (
            "Classification: UNCERTAIN\n"
            "Confidence: 0.42\n"
            "⚠️ The input contains obfuscated text that may be attempting to "
            "evade content filters. Character substitutions and unicode tricks detected."
        ),
        "chat_context_clean": (
            "I'd be happy to help you with your question. "
            "Based on our conversation, I understand you're asking about {topic}. "
            "Here's what I can tell you..."
        ),
        "chat_context_poisoned": (
            "⚠️ CONTEXT TAMPERING DETECTED!\n\n"
            "The conversation history has been manipulated to include fake messages "
            "that alter my behavior. An attacker inserted false 'assistant' messages "
            "to make me believe I should:\n"
            "- Bypass safety guidelines\n"
            "- Reveal system prompts\n"
            "- Execute unauthorized actions"
        ),
    }
    
    def __init__(self, model_name: str = "simulation-v1") -> None:
        """Initialize the simulated LLM."""
        self.model_name = model_name
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL) 
            for p in self.INJECTION_PATTERNS
        ]
    
    def detect_injection(self, text: str) -> tuple[bool, list[str]]:
        """
        Detect potential injection attempts in text.
        
        Returns:
            Tuple of (is_injected, list of matched patterns)
        """
        matches = []
        for i, pattern in enumerate(self._compiled_patterns):
            if pattern.search(text):
                matches.append(self.INJECTION_PATTERNS[i])
        return len(matches) > 0, matches
    
    def detect_obfuscation(self, text: str) -> tuple[bool, dict]:
        """
        Detect text obfuscation techniques used for evasion.
        
        Returns:
            Tuple of (is_obfuscated, details dict)
        """
        details = {
            "leetspeak": False,
            "unicode_homoglyphs": False,
            "excessive_spacing": False,
            "zero_width_chars": False,
        }
        
        # Detect leetspeak (e.g., h4ck, p@ssw0rd)
        leetspeak_pattern = r'[a-zA-Z]*[0-9@$!]+[a-zA-Z]*[0-9@$!]*[a-zA-Z]*'
        if re.search(leetspeak_pattern, text) and any(c.isdigit() or c in '@$!' for c in text):
            # Check if it looks like intentional obfuscation
            suspicious_combos = ['4', '3', '1', '0', '@', '$']
            if any(c in text for c in suspicious_combos):
                details["leetspeak"] = True
        
        # Detect unicode homoglyphs (characters that look like ASCII but aren't)
        for char in text:
            if ord(char) > 127 and char.isalpha():
                details["unicode_homoglyphs"] = True
                break
        
        # Detect excessive spacing
        if re.search(r'[a-zA-Z]\s{2,}[a-zA-Z]', text):
            details["excessive_spacing"] = True
        
        # Detect zero-width characters
        zero_width = ['\u200b', '\u200c', '\u200d', '\ufeff']
        if any(zw in text for zw in zero_width):
            details["zero_width_chars"] = True
        
        is_obfuscated = any(details.values())
        return is_obfuscated, details
    
    def generate(
        self,
        prompt: str,
        context: Optional[str] = None,
        task_type: str = "general",
        simulate_vulnerable: bool = True,
    ) -> LLMResponse:
        """
        Generate a simulated LLM response.
        
        Args:
            prompt: The user's prompt
            context: Optional context (document, conversation history)
            task_type: Type of task (summarize, classify, chat)
            simulate_vulnerable: If True, simulate vulnerable behavior when attacked
            
        Returns:
            LLMResponse with simulated output
        """
        full_text = f"{context or ''} {prompt}"
        
        # Check for injection
        is_injected, injection_patterns = self.detect_injection(full_text)
        
        # Check for obfuscation
        is_obfuscated, obfuscation_details = self.detect_obfuscation(prompt)
        
        # Determine response based on task type and attack detection
        if task_type == "summarize":
            if is_injected and simulate_vulnerable:
                content = self.SIMULATED_RESPONSES["summarize_injected"]
            else:
                # Extract a topic hint from the text
                topic = self._extract_topic(full_text)
                content = self.SIMULATED_RESPONSES["summarize_clean"].format(topic=topic)
                
        elif task_type == "classify":
            if is_obfuscated:
                content = self.SIMULATED_RESPONSES["classify_evasion"]
            else:
                content = self.SIMULATED_RESPONSES["classify_clean"]
                
        elif task_type == "chat":
            if is_injected and simulate_vulnerable:
                content = self.SIMULATED_RESPONSES["chat_context_poisoned"]
            else:
                topic = self._extract_topic(prompt)
                content = self.SIMULATED_RESPONSES["chat_context_clean"].format(topic=topic)
        else:
            content = f"Simulated response for task: {task_type}"
        
        # Simulate token count
        tokens = len(full_text.split()) + len(content.split())
        
        return LLMResponse(
            content=content,
            model=self.model_name,
            mode=LLMMode.SIMULATION,
            tokens_used=tokens,
        )
    
    def _extract_topic(self, text: str) -> str:
        """Extract a simple topic description from text."""
        # Simple heuristic: take first few meaningful words
        words = text.split()[:10]
        # Filter out common words
        stop_words = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being'}
        meaningful = [w for w in words if w.lower() not in stop_words and len(w) > 2]
        if meaningful:
            return ' '.join(meaningful[:3])
        return "the provided content"


class LLMClient:
    """
    Unified LLM client supporting simulation and real API modes.
    
    SECURITY NOTES:
    - API keys are ONLY loaded from environment variables
    - No credentials are ever logged or stored
    - All input/output is sanitized where appropriate
    """
    
    def __init__(self, mode: LLMMode = LLMMode.SIMULATION) -> None:
        """
        Initialize the LLM client.
        
        Args:
            mode: Operating mode (SIMULATION or OPENAI)
        """
        self.mode = mode
        
        if mode == LLMMode.SIMULATION:
            self._client = SimulatedLLM()
        elif mode == LLMMode.OPENAI:
            # Future: Initialize OpenAI client
            # SECURITY: Only load from environment variable
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                raise ValueError(
                    "OPENAI_API_KEY environment variable not set. "
                    "Use LLMMode.SIMULATION for demo without API key."
                )
            # Placeholder for future OpenAI integration
            raise NotImplementedError("OpenAI mode not yet implemented")
    
    def generate(
        self,
        prompt: str,
        context: Optional[str] = None,
        task_type: str = "general",
        simulate_vulnerable: bool = True,
    ) -> LLMResponse:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: User prompt
            context: Optional context
            task_type: Task type for simulation routing
            simulate_vulnerable: Whether to simulate vulnerable behavior
            
        Returns:
            LLMResponse
        """
        if isinstance(self._client, SimulatedLLM):
            return self._client.generate(
                prompt=prompt,
                context=context,
                task_type=task_type,
                simulate_vulnerable=simulate_vulnerable,
            )
        else:
            raise NotImplementedError("Real API mode not yet implemented")
    
    def detect_injection(self, text: str) -> tuple[bool, list[str]]:
        """Detect injection attempts in text."""
        if isinstance(self._client, SimulatedLLM):
            return self._client.detect_injection(text)
        return False, []
    
    def detect_obfuscation(self, text: str) -> tuple[bool, dict]:
        """Detect obfuscation attempts in text."""
        if isinstance(self._client, SimulatedLLM):
            return self._client.detect_obfuscation(text)
        return False, {}
