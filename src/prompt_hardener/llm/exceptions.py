class LLMError(Exception):
    """Base class for normalized LLM client errors."""


class LLMConfigurationError(LLMError):
    """Raised for invalid provider or request configuration."""


class LLMTimeoutError(LLMError):
    """Raised when a provider call times out."""


class LLMRateLimitError(LLMError):
    """Raised when a provider call is rate limited."""


class LLMProviderError(LLMError):
    """Raised for provider SDK or transport failures."""


class LLMResponseFormatError(LLMError):
    """Raised when structured output cannot be parsed."""
