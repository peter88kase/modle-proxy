"""按测试任务生效的请求预算与时长上限。

自动验收会产生真实的第三方调用和费用，所以每个任务都必须有硬边界：
请求次数上限、总时长上限。预算通过 ``ContextVar`` 传播，任何在任务协程内部
发起的请求都会先扣减；超出后不再发出请求，由调用方把该项记为“未测试”，
绝不允许“预算用完了还继续跑”。
"""

from __future__ import annotations

import time
from contextvars import ContextVar, Token
from dataclasses import dataclass, field


@dataclass
class Budget:
    max_requests: int = 120
    max_seconds: float = 900.0
    started: float = field(default_factory=time.monotonic)
    used: int = 0
    exhausted_reason: str = ""

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def remaining_seconds(self) -> float:
        return max(0.0, self.max_seconds - self.elapsed())

    def take(self) -> bool:
        """Reserve one request.  Returns False once the task is out of budget."""
        if self.exhausted_reason:
            return False
        if self.used >= self.max_requests:
            self.exhausted_reason = f"请求预算已用尽（上限 {self.max_requests} 次），后续用例未执行"
            return False
        if self.remaining_seconds() <= 0:
            self.exhausted_reason = f"测试时长超过上限（{int(self.max_seconds)} 秒），后续用例未执行"
            return False
        self.used += 1
        return True

    def snapshot(self) -> dict:
        return {
            "max_requests": self.max_requests,
            "used_requests": self.used,
            "max_seconds": self.max_seconds,
            "elapsed_seconds": round(self.elapsed(), 1),
            "exhausted_reason": self.exhausted_reason,
        }


_CURRENT: ContextVar[Budget | None] = ContextVar("bedrock_budget", default=None)


def set_budget(budget: Budget) -> Token:
    return _CURRENT.set(budget)


def reset_budget(token: Token) -> None:
    try:
        _CURRENT.reset(token)
    except ValueError:  # pragma: no cover - token from another context
        pass


def current_budget() -> Budget | None:
    return _CURRENT.get()


def take_request() -> tuple[bool, str]:
    """Consume one request slot.  Outside a task there is no limit."""
    budget = _CURRENT.get()
    if budget is None:
        return True, ""
    if budget.take():
        return True, ""
    return False, budget.exhausted_reason
