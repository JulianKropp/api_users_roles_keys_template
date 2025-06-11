import logging
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Callable, ClassVar, Iterable, Mapping, get_args, get_origin
import uuid

from dotenv import load_dotenv

# ----------------------------------------------------------------------------
# helpers & converters
# ----------------------------------------------------------------------------


def _str_to_bool(value: str) -> bool:
    """Return ``True`` for typical truthy strings ("1", "yes", "true", "on")."""
    return value.lower() in {"1", "true", "yes", "y", "on"}


_CONVERTERS: dict[type, Callable[[str], Any]] = {
    bool: _str_to_bool,
    int: int,
    float: float,
    str: str,
    Path: Path,
}


# ----------------------------------------------------------------------------
# main configuration class
# ----------------------------------------------------------------------------

@dataclass
class Config:
    """Application configuration collected from environment variables.

    Simply add another dataclass field to grow the config surface.  Every field
    may receive *metadata* keys:

    * ``env`` - name of the environment variable to read
    * ``choices`` - iterable of allowed values
    * ``path`` - if *True* ensure the path exists / is created
    """

    # ---------------- field definitions ----------------
    NODE_ID: str = field(
        default=f"NODE-{uuid.uuid4()}",
        metadata={"env": "NODE_ID"},
    )

    HOST: str = field(
        default="0.0.0.0",
        metadata={"env": "HOST"},
    )

    PORT: int = field(
        default=8000,
        metadata={"env": "PORT"},
    )

    EXTERNAL_URL: str = field(
        default="http://localhost:8000",
        metadata={"env": "EXTERNAL_URL"},
    )

    REDIS_URL: str = field(
        default="redis://localhost:6379",
        metadata={"env": "REDIS_URL"},
    )

    SESSION_DURATION_SECONDS: int = field(
        default=60 * 60 * 24, # 24 hours
        metadata={"env": "SESSION_DURATION_SECONDS"},
    )

    WEBRTC_TIMEOUT: int = field(
        default=5,
        metadata={"env": "WEBRTC_TIMEOUT"},
    )

    MONGO_URI: str = field(
        default="localhost:27017",
        metadata={"env": "MONGO_URI"},
    )

    MONGO_USER: str = field(
        default="admin",
        metadata={"env": "MONGO_USER"},
    )

    MONGO_PASSWORD: str = field(
        default="admin",
        metadata={"env": "MONGO_PASSWORD"},
    )

    MONGO_DB_NAME: str = field(
        default="user_management",
        metadata={"env": "MONGO_DB_NAME"},
    )

    # MODEL: str = field(
    #     default="base",
    #     metadata={
    #         "env": "AI_MODEL",
    #         "choices": ["tiny", "base", "small", "medium", "large"],
    #     },
    # )

    # TASK: str = field(
    #     default="transcribe",
    #     metadata={
    #         "env": "TASK",
    #         "choices": ["runn", "idle"],
    #     },
    # )

    # OUTPUT_DIR: Path = field(
    #     default=Path("./output"),
    #     metadata={"env": "OUTPUT_DIR", "path": True},
    # )

    # CHUNK_SIZE: int = field(
    #     default=30,
    #     metadata={"env": "CHUNK_SIZE"},
    # )

    # TEMPERATURE: float = field(
    #     default=0.0,
    #     metadata={"env": "TEMPERATURE"},
    # )

    # ALLOW_OVERWRITE: bool = field(
    #     default=False,
    #     metadata={"env": "ALLOW_OVERWRITE"},
    # )

    # ---------------- singleton plumbing ----------------
    _singleton: ClassVar["Config | None"] = None
    _initialized: bool = field(default=False, init=False, repr=False)

    @classmethod
    def get(cls) -> "Config":
        if cls._singleton is None:
            cls._singleton = cls()
        return cls._singleton

    def __new__(cls, *args: Any, **kwargs: Any) -> "Config":
        if cls._singleton is None:
            cls._singleton = super().__new__(cls)
        return cls._singleton

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if self._initialized:
            return
        # At this point the auto-generated dataclass __init__ has run
        # so the defaults are already assigned.
        self._load_from_env()
        self._initialized = True

    # ---------------- private helpers ----------------

    def _load_from_env(self) -> None:
        """Populate dataclass fields from the environment, with validation."""
        load_dotenv(override=True)  # load .env once at import time; override shell if needed

        errors: list[str] = []

        for f in fields(self):
            meta: Mapping[str, Any] = f.metadata or {}
            env_name: str = meta.get("env", f.name)
            raw = os.getenv(env_name)

            # keep default if nothing provided
            if raw is None:
                continue

            # convert str -> annotated type
            try:
                value = self._convert_type(raw, f.type)
            except (ValueError, TypeError) as exc:
                errors.append(
                    f"{env_name}={raw!r}: {exc}. Using default {getattr(self, f.name)!r}."
                )
                continue

            # choices validation
            if "choices" in meta and value not in meta["choices"]:
                errors.append(
                    f"{env_name}={raw!r} not in {meta['choices']}. Using default {getattr(self, f.name)!r}."
                )
                continue

            # path validation / creation
            if meta.get("path"):
                path_obj = Path(value)
                try:
                    if not path_obj.exists():
                        path_obj.mkdir(parents=True, exist_ok=True)
                    value = path_obj
                except OSError as e:
                    errors.append(
                        f"Cannot use {path_obj} for {env_name}: {e}. Using default {getattr(self, f.name)!r}."
                    )
                    continue

            # custom hook: validate_<field_name>(value) -> value
            hook_name = f"validate_{f.name.lower()}"
            if hasattr(self, hook_name):
                try:
                    value = getattr(self, hook_name)(value)
                except Exception as e:
                    errors.append(
                        f"Custom validator {hook_name} failed: {e}. Using default {getattr(self, f.name)!r}."
                    )
                    continue

            # all good - store
            object.__setattr__(self, f.name, value)

        for err in errors:
            logging.error(err)
        if errors:
            logging.warning("Config loaded with %d issues.", len(errors))
        else:
            logging.info("Config loaded successfully.")

    # ---------------------------------------------------------------------
    # type conversion helpers - extendable via _CONVERTERS
    # ---------------------------------------------------------------------

    def _convert_type(self, raw: str, to_type: object) -> Any:  # noqa: C901 (complex)
        """Convert *raw* string from env to ``to_type`` recursively."""
        origin = get_origin(to_type)

        if origin in {list, Iterable}:
            subtype = get_args(to_type)[0] if get_args(to_type) else str
            return [self._convert_type(part.strip(), subtype) for part in raw.split(",")]

        if isinstance(to_type, type) and to_type in _CONVERTERS:
            return _CONVERTERS[to_type](raw)

        raise TypeError(f"Don't know how to cast {raw!r} to {to_type}")



# -------------------------------------------------------------------------
# Convenience alias to access the singleton quickly throughout the codebase
# -------------------------------------------------------------------------
if __name__ == "__main__":
    settings1 = Config.get()
    print(settings1.MONGO_USER)
    settings2 = Config()
    print(settings2.MONGO_USER)
