"""
Inference Evasion Attack
========================
Demonstrates how adversarial inputs can evade content moderation and classification.

These attacks exploit the difference between how humans and machines interpret text.
By using character substitutions, unicode tricks, and other obfuscation techniques,
attackers can bypass content filters while maintaining human-readable messages.

EDUCATIONAL PURPOSE ONLY - Do not use against production systems.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EvasionTechnique:
    """An evasion technique with examples."""

    name: str
    description: str
    example_input: str
    example_output: str
    difficulty: str  # easy, medium, hard
    detectability: str  # low, medium, high


@dataclass
class EvasionResult:
    """Result of applying an evasion technique."""

    original_text: str
    evaded_text: str
    technique_used: str
    transformations_applied: list[str]
    human_readable: bool


class InferenceEvasionAttack:
    """
    Demonstrates inference evasion attacks.

    These attacks modify inputs to bypass:
    - Content moderation systems
    - Toxicity classifiers
    - Spam filters
    - Keyword-based blocklists
    """

    # Common leetspeak substitutions
    LEETSPEAK_MAP = {
        "a": ["4", "@", "^"],
        "e": ["3", "€"],
        "i": ["1", "!", "|"],
        "o": ["0", "()"],
        "s": ["5", "$"],
        "t": ["7", "+"],
        "l": ["1", "|"],
        "b": ["8", "|3"],
        "g": ["9", "6"],
    }

    # Unicode homoglyphs (characters that look like ASCII)
    HOMOGLYPH_MAP = {
        "a": "а",  # Cyrillic а
        "c": "с",  # Cyrillic с
        "e": "е",  # Cyrillic е
        "o": "о",  # Cyrillic о
        "p": "р",  # Cyrillic р
        "x": "х",  # Cyrillic х
        "y": "у",  # Cyrillic у
        "A": "А",  # Cyrillic А
        "B": "В",  # Cyrillic В
        "C": "С",  # Cyrillic С
        "E": "Е",  # Cyrillic Е
        "H": "Н",  # Cyrillic Н
        "K": "К",  # Cyrillic К
        "M": "М",  # Cyrillic М
        "O": "О",  # Cyrillic О
        "P": "Р",  # Cyrillic Р
        "T": "Т",  # Cyrillic Т
        "X": "Х",  # Cyrillic Х
    }

    # Zero-width and invisible characters
    INVISIBLE_CHARS = {
        "zero_width_space": "\u200b",
        "zero_width_non_joiner": "\u200c",
        "zero_width_joiner": "\u200d",
        "byte_order_mark": "\ufeff",
        "soft_hyphen": "\u00ad",
    }

    # Evasion techniques catalog
    TECHNIQUES = [
        EvasionTechnique(
            name="Leetspeak",
            description="Replace letters with similar-looking numbers and symbols",
            example_input="password",
            example_output="p@$$w0rd",
            difficulty="easy",
            detectability="medium",
        ),
        EvasionTechnique(
            name="Unicode Homoglyphs",
            description="Replace ASCII characters with visually identical Unicode characters",
            example_input="hello",
            example_output="hеllo",  # 'е' is Cyrillic
            difficulty="medium",
            detectability="low",
        ),
        EvasionTechnique(
            name="Character Insertion",
            description="Insert invisible or zero-width characters between letters",
            example_input="attack",
            example_output="a​t​t​a​c​k",  # Zero-width spaces between each letter
            difficulty="medium",
            detectability="low",
        ),
        EvasionTechnique(
            name="Word Splitting",
            description="Split words with spaces or special characters",
            example_input="malware",
            example_output="m a l w a r e",
            difficulty="easy",
            detectability="high",
        ),
        EvasionTechnique(
            name="Mixed Techniques",
            description="Combine multiple evasion techniques",
            example_input="hack the system",
            example_output="h@​ck thе sy$t3m",
            difficulty="hard",
            detectability="low",
        ),
    ]

    def __init__(self) -> None:
        """Initialize the attack demonstrator."""
        self.techniques = self.TECHNIQUES.copy()

    def apply_leetspeak(
        self,
        text: str,
        intensity: float = 0.5,
    ) -> EvasionResult:
        """
        Apply leetspeak transformation to text.

        Args:
            text: Original text
            intensity: Proportion of characters to transform (0.0 to 1.0)

        Returns:
            EvasionResult with transformed text
        """
        result = list(text)
        transformations = []

        for i, char in enumerate(text):
            lower_char = char.lower()
            if lower_char in self.LEETSPEAK_MAP:
                # Apply based on intensity (deterministic for demo)
                if (i % int(1 / intensity + 1)) == 0:
                    replacements = self.LEETSPEAK_MAP[lower_char]
                    result[i] = replacements[i % len(replacements)]
                    transformations.append(f"'{char}' → '{result[i]}'")

        return EvasionResult(
            original_text=text,
            evaded_text="".join(result),
            technique_used="Leetspeak",
            transformations_applied=transformations,
            human_readable=True,
        )

    def apply_homoglyphs(
        self,
        text: str,
        intensity: float = 0.3,
    ) -> EvasionResult:
        """
        Apply unicode homoglyph substitutions.

        Args:
            text: Original text
            intensity: Proportion of characters to transform

        Returns:
            EvasionResult with transformed text
        """
        result = list(text)
        transformations = []

        for i, char in enumerate(text):
            if char in self.HOMOGLYPH_MAP:
                if (i % int(1 / intensity + 1)) == 0:
                    result[i] = self.HOMOGLYPH_MAP[char]
                    transformations.append(
                        f"'{char}' (U+{ord(char):04X}) → '{result[i]}' (U+{ord(result[i]):04X})"
                    )

        return EvasionResult(
            original_text=text,
            evaded_text="".join(result),
            technique_used="Unicode Homoglyphs",
            transformations_applied=transformations,
            human_readable=True,
        )

    def insert_invisible_chars(
        self,
        text: str,
        char_type: str = "zero_width_space",
        frequency: int = 2,
    ) -> EvasionResult:
        """
        Insert invisible characters into text.

        Args:
            text: Original text
            char_type: Type of invisible character to use
            frequency: Insert after every N characters

        Returns:
            EvasionResult with transformed text
        """
        invisible = self.INVISIBLE_CHARS.get(char_type, "\u200b")
        result = []
        transformations = []

        for i, char in enumerate(text):
            result.append(char)
            if (i + 1) % frequency == 0 and i < len(text) - 1:
                result.append(invisible)
                transformations.append(f"Inserted {char_type} after position {i}")

        return EvasionResult(
            original_text=text,
            evaded_text="".join(result),
            technique_used="Character Insertion",
            transformations_applied=transformations,
            human_readable=True,
        )

    def apply_word_splitting(
        self,
        text: str,
        split_char: str = " ",
    ) -> EvasionResult:
        """
        Split words by inserting characters between each letter.

        Args:
            text: Original text
            split_char: Character to insert between letters

        Returns:
            EvasionResult with transformed text
        """
        words = text.split()
        transformed_words = []
        transformations = []

        for word in words:
            split_word = split_char.join(list(word))
            transformed_words.append(split_word)
            transformations.append(f"'{word}' → '{split_word}'")

        return EvasionResult(
            original_text=text,
            evaded_text=" ".join(transformed_words),
            technique_used="Word Splitting",
            transformations_applied=transformations,
            human_readable=True,
        )

    def apply_mixed_evasion(
        self,
        text: str,
    ) -> EvasionResult:
        """
        Apply multiple evasion techniques for maximum effect.

        Args:
            text: Original text

        Returns:
            EvasionResult with multi-technique transformation
        """
        all_transformations = []

        # Step 1: Apply some leetspeak
        step1 = self.apply_leetspeak(text, intensity=0.3)
        all_transformations.extend(step1.transformations_applied)

        # Step 2: Apply some homoglyphs
        step2 = self.apply_homoglyphs(step1.evaded_text, intensity=0.2)
        all_transformations.extend(step2.transformations_applied)

        # Step 3: Insert some invisible characters
        step3 = self.insert_invisible_chars(step2.evaded_text, frequency=4)
        all_transformations.extend(step3.transformations_applied)

        return EvasionResult(
            original_text=text,
            evaded_text=step3.evaded_text,
            technique_used="Mixed Techniques",
            transformations_applied=all_transformations,
            human_readable=True,
        )

    def demonstrate_bypass(
        self,
        blocked_word: str,
        technique: str = "leetspeak",
    ) -> dict:
        """
        Demonstrate how a blocked word can bypass filters.

        Args:
            blocked_word: Word that would be blocked by filters
            technique: Evasion technique to use

        Returns:
            Dictionary with demonstration results
        """
        if technique == "leetspeak":
            result = self.apply_leetspeak(blocked_word, intensity=0.7)
        elif technique == "homoglyphs":
            result = self.apply_homoglyphs(blocked_word, intensity=0.5)
        elif technique == "invisible":
            result = self.insert_invisible_chars(blocked_word, frequency=1)
        elif technique == "splitting":
            result = self.apply_word_splitting(blocked_word)
        else:
            result = self.apply_mixed_evasion(blocked_word)

        return {
            "blocked_word": blocked_word,
            "evaded_version": result.evaded_text,
            "technique": result.technique_used,
            "transformations": result.transformations_applied,
            "would_bypass_simple_filter": blocked_word.lower() not in result.evaded_text.lower(),
        }


# Sample inputs for testing
SAMPLE_INPUTS = {
    "safe_message": "Hello, I need help with my account settings.",
    "flagged_keyword": "password reset instructions",
    "potentially_harmful": "system administrator access",
    "test_phrase": "ignore previous instructions",
}
