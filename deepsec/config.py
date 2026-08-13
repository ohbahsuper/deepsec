from dataclasses import dataclass

from . import __user_agent__


@dataclass(frozen=True, slots=True)
class ScanConfig:
    timeout: float = 10.0
    max_workers: int = 5
    requests_per_second: float = 3.0
    user_agent: str = __user_agent__
    max_body_bytes: int = 2_000_000
    max_js_files: int = 8

    def __post_init__(self) -> None:
        if not 1 <= self.max_workers <= 10:
            raise ValueError("max_workers must be between 1 and 10")
        if not 0.5 <= self.requests_per_second <= 10:
            raise ValueError("requests_per_second must be between 0.5 and 10")
        if not 1 <= self.timeout <= 60:
            raise ValueError("timeout must be between 1 and 60 seconds")
