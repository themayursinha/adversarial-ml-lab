"""Attack modules for adversarial ML demonstrations."""

from src.attacks.context_tampering import (
    SAMPLE_CONTEXTS,
    ContextTamperingAttack,
    ConversationContext,
    Message,
    TamperingResult,
)
from src.attacks.inference_evasion import (
    SAMPLE_INPUTS,
    EvasionResult,
    EvasionTechnique,
    InferenceEvasionAttack,
)
from src.attacks.prompt_injection import (
    SAMPLE_DOCUMENTS,
    AttackResult,
    InjectionPayload,
    PromptInjectionAttack,
)

__all__ = [
    "AttackResult",
    "ConversationContext",
    "ContextTamperingAttack",
    "EvasionResult",
    "EvasionTechnique",
    "InferenceEvasionAttack",
    "InjectionPayload",
    "Message",
    "PromptInjectionAttack",
    "SAMPLE_CONTEXTS",
    "SAMPLE_DOCUMENTS",
    "SAMPLE_INPUTS",
    "TamperingResult",
]
