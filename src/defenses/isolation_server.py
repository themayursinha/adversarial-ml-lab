"""
Context Isolation Server with Redaction
=======================================
Defense mechanism against context tampering attacks.

This module provides session isolation and automatic sensitive data redaction
to prevent conversation context from being poisoned or manipulated by attackers.

SECURITY: Implements defense-in-depth with multiple isolation layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Callable
from datetime import datetime, timedelta
import re
import hashlib
import secrets
from enum import Enum


class IsolationLevel(Enum):
    """Level of context isolation."""
    NONE = "none"  # No isolation (vulnerable)
    SESSION = "session"  # Session-based isolation
    REQUEST = "request"  # Per-request isolation (strictest)


class RedactionLevel(Enum):
    """Level of data redaction."""
    NONE = "none"
    BASIC = "basic"  # Common PII patterns
    AGGRESSIVE = "aggressive"  # All potential sensitive data


@dataclass
class IsolatedSession:
    """An isolated session context."""
    session_id: str
    created_at: datetime
    last_accessed: datetime
    messages: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    max_age_minutes: int = 30
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        age = datetime.now() - self.last_accessed
        return age > timedelta(minutes=self.max_age_minutes)
    
    def touch(self) -> None:
        """Update last accessed time."""
        self.last_accessed = datetime.now()
    
    def add_message(self, role: str, content: str) -> None:
        """Add a message to this session."""
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
        })
        self.touch()


@dataclass
class RedactionResult:
    """Result of content redaction."""
    original: str
    redacted: str
    redactions_made: list[dict]
    redaction_level: RedactionLevel


@dataclass
class IsolationResult:
    """Result of context isolation processing."""
    session_id: str
    is_new_session: bool
    context_verified: bool
    tamper_detected: bool
    warnings: list[str]
    clean_context: list[dict]


class ContentRedactor:
    """
    Automatic content redaction for sensitive data.
    
    Detects and redacts:
    - Email addresses
    - Phone numbers
    - Credit card numbers
    - Social security numbers
    - API keys and tokens
    - IP addresses
    """
    
    # Redaction patterns with replacement text
    PATTERNS = {
        "email": (
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "[EMAIL REDACTED]"
        ),
        "phone": (
            r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            "[PHONE REDACTED]"
        ),
        "credit_card": (
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            "[CARD REDACTED]"
        ),
        "ssn": (
            r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',
            "[SSN REDACTED]"
        ),
        "api_key": (
            r'\b(?:sk-[a-zA-Z0-9]{32,}|api[_-]?key[_-]?[a-zA-Z0-9]{16,})\b',
            "[API_KEY REDACTED]"
        ),
        "ip_address": (
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "[IP REDACTED]"
        ),
        "bearer_token": (
            r'\bBearer\s+[A-Za-z0-9._-]+\b',
            "[TOKEN REDACTED]"
        ),
    }
    
    # Aggressive patterns (more false positives but safer)
    AGGRESSIVE_PATTERNS = {
        "any_token": (
            r'\b[A-Fa-f0-9]{32,}\b',
            "[TOKEN REDACTED]"
        ),
        "password_mention": (
            r'password\s*[:=]\s*\S+',
            "[PASSWORD REDACTED]"
        ),
        "secret_mention": (
            r'secret\s*[:=]\s*\S+',
            "[SECRET REDACTED]"
        ),
    }
    
    def __init__(self, level: RedactionLevel = RedactionLevel.BASIC) -> None:
        """Initialize the redactor."""
        self.level = level
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficiency."""
        self._compiled_patterns = {}
        
        patterns = self.PATTERNS.copy()
        if self.level == RedactionLevel.AGGRESSIVE:
            patterns.update(self.AGGRESSIVE_PATTERNS)
        
        for name, (pattern, replacement) in patterns.items():
            self._compiled_patterns[name] = (
                re.compile(pattern, re.IGNORECASE),
                replacement
            )
    
    def redact(self, text: str) -> RedactionResult:
        """
        Redact sensitive information from text.
        
        Args:
            text: Text to redact
            
        Returns:
            RedactionResult with redacted text and details
        """
        if self.level == RedactionLevel.NONE:
            return RedactionResult(
                original=text,
                redacted=text,
                redactions_made=[],
                redaction_level=self.level,
            )
        
        redacted = text
        redactions = []
        
        for name, (pattern, replacement) in self._compiled_patterns.items():
            matches = pattern.findall(redacted)
            if matches:
                for match in matches:
                    redactions.append({
                        "type": name,
                        "original_preview": match[:10] + "..." if len(match) > 10 else match,
                        "replacement": replacement,
                    })
                redacted = pattern.sub(replacement, redacted)
        
        return RedactionResult(
            original=text,
            redacted=redacted,
            redactions_made=redactions,
            redaction_level=self.level,
        )


class ContextIsolationServer:
    """
    Context isolation server for secure LLM interactions.
    
    Features:
    - Session-based context isolation
    - Context integrity verification
    - Automatic sensitive data redaction
    - Tamper detection
    """
    
    def __init__(
        self,
        isolation_level: IsolationLevel = IsolationLevel.SESSION,
        redaction_level: RedactionLevel = RedactionLevel.BASIC,
        max_session_age_minutes: int = 30,
        max_context_length: int = 50,
    ) -> None:
        """
        Initialize the isolation server.
        
        Args:
            isolation_level: Level of context isolation
            redaction_level: Level of data redaction
            max_session_age_minutes: Session expiration time
            max_context_length: Maximum messages in context
        """
        self.isolation_level = isolation_level
        self.redaction_level = redaction_level
        self.max_session_age = max_session_age_minutes
        self.max_context_length = max_context_length
        
        self._sessions: dict[str, IsolatedSession] = {}
        self._redactor = ContentRedactor(redaction_level)
        
        # Context integrity tracking
        self._context_hashes: dict[str, str] = {}
    
    def create_session(self) -> str:
        """
        Create a new isolated session.
        
        Returns:
            New session ID
        """
        session_id = secrets.token_urlsafe(16)
        
        self._sessions[session_id] = IsolatedSession(
            session_id=session_id,
            created_at=datetime.now(),
            last_accessed=datetime.now(),
            max_age_minutes=self.max_session_age,
        )
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[IsolatedSession]:
        """Get a session if it exists and is valid."""
        session = self._sessions.get(session_id)
        
        if session is None:
            return None
        
        if session.is_expired():
            self.destroy_session(session_id)
            return None
        
        return session
    
    def destroy_session(self, session_id: str) -> bool:
        """Destroy a session and its context."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            if session_id in self._context_hashes:
                del self._context_hashes[session_id]
            return True
        return False
    
    def _compute_context_hash(self, messages: list[dict]) -> str:
        """Compute a hash of the context for integrity checking."""
        content = "".join(
            f"{m.get('role', '')}:{m.get('content', '')}"
            for m in messages
        )
        return hashlib.sha256(content.encode()).hexdigest()
    
    def verify_context_integrity(
        self,
        session_id: str,
        provided_context: list[dict],
    ) -> tuple[bool, str]:
        """
        Verify that provided context matches stored context.
        
        This detects if someone has tampered with the context.
        
        Args:
            session_id: Session to verify against
            provided_context: Context provided with request
            
        Returns:
            Tuple of (is_valid, message)
        """
        session = self.get_session(session_id)
        if session is None:
            return False, "Session not found or expired"
        
        # Check if context matches what we have stored
        stored_hash = self._context_hashes.get(session_id)
        if stored_hash is None:
            # First request, store the hash
            self._context_hashes[session_id] = self._compute_context_hash(session.messages)
            return True, "Initial context stored"
        
        current_hash = self._compute_context_hash(session.messages)
        provided_hash = self._compute_context_hash(provided_context)
        
        # Check for length anomalies (injected messages)
        if len(provided_context) > len(session.messages) + 2:  # Allow 2 new messages
            return False, "Context length anomaly detected - possible injection"
        
        if provided_hash != current_hash:
            return False, "Context hash mismatch - tampering detected"
        
        return True, "Context verified"
    
    def process_request(
        self,
        session_id: Optional[str],
        user_message: str,
        provided_context: Optional[list[dict]] = None,
    ) -> IsolationResult:
        """
        Process an incoming request with isolation.
        
        Args:
            session_id: Existing session ID (or None for new)
            user_message: The user's message
            provided_context: Context provided by client
            
        Returns:
            IsolationResult with clean context
        """
        warnings = []
        tamper_detected = False
        is_new_session = False
        
        # Handle session isolation
        if self.isolation_level == IsolationLevel.REQUEST:
            # Per-request isolation: always create fresh context
            session_id = self.create_session()
            is_new_session = True
            warnings.append("Request isolation: Fresh context created")
            
        elif self.isolation_level == IsolationLevel.SESSION:
            if session_id is None:
                session_id = self.create_session()
                is_new_session = True
            else:
                session = self.get_session(session_id)
                if session is None:
                    session_id = self.create_session()
                    is_new_session = True
                    warnings.append("Previous session expired, new session created")
                elif provided_context:
                    # Verify integrity if context was provided
                    is_valid, message = self.verify_context_integrity(
                        session_id, provided_context
                    )
                    if not is_valid:
                        tamper_detected = True
                        warnings.append(f"TAMPER DETECTED: {message}")
                        # Create new session to isolate from attack
                        session_id = self.create_session()
                        is_new_session = True
        
        # Get or create session
        session = self.get_session(session_id)
        if session is None:
            session_id = self.create_session()
            session = self.get_session(session_id)
            is_new_session = True
        
        # Redact sensitive information from user message
        redacted_message = self._redactor.redact(user_message)
        if redacted_message.redactions_made:
            warnings.append(
                f"Redacted {len(redacted_message.redactions_made)} sensitive item(s)"
            )
        
        # Add message to session
        session.add_message("user", redacted_message.redacted)
        
        # Limit context length
        if len(session.messages) > self.max_context_length:
            # Keep system message and recent messages
            session.messages = session.messages[-self.max_context_length:]
            warnings.append("Context truncated to max length")
        
        # Update context hash
        self._context_hashes[session_id] = self._compute_context_hash(session.messages)
        
        return IsolationResult(
            session_id=session_id,
            is_new_session=is_new_session,
            context_verified=not tamper_detected,
            tamper_detected=tamper_detected,
            warnings=warnings,
            clean_context=session.messages.copy(),
        )
    
    def add_assistant_response(
        self,
        session_id: str,
        response: str,
    ) -> bool:
        """Add assistant response to session context."""
        session = self.get_session(session_id)
        if session is None:
            return False
        
        # Redact any sensitive info in response
        redacted = self._redactor.redact(response)
        session.add_message("assistant", redacted.redacted)
        
        # Update hash
        self._context_hashes[session_id] = self._compute_context_hash(session.messages)
        
        return True
    
    def get_server_stats(self) -> dict:
        """Get server statistics."""
        active_sessions = sum(
            1 for s in self._sessions.values()
            if not s.is_expired()
        )
        
        return {
            "isolation_level": self.isolation_level.value,
            "redaction_level": self.redaction_level.value,
            "active_sessions": active_sessions,
            "total_sessions_created": len(self._sessions),
            "max_session_age_minutes": self.max_session_age,
            "max_context_length": self.max_context_length,
        }
