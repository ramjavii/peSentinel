from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

from pesentinel.protection.types import Right

F = TypeVar("F", bound=Callable[..., Any])


def requires_capability(obj: str, right: Right) -> Callable[[F], F]:
    """Declarative protection decorator (Ch.14 §9.1).

    Declares, at definition time, that calling the decorated function
    requires ``right`` on ``obj``. Enforced at call time via
    ``check_permission`` — combining load-time declaration with
    runtime kernel enforcement, as the text prescribes.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from pesentinel.protection import stack_inspection
            from pesentinel.protection.kernel import ProtectionKernel

            kernel = ProtectionKernel.instance()
            stack_inspection.check_permission(kernel, obj, right)
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
