"""CDR 예외."""


class CDRError(Exception):
    """처리 중 오류."""


class BlockedError(CDRError):
    """무해화가 불가능하여 파일을 차단해야 하는 경우."""

    def __init__(self, reason: str, category: str = "policy") -> None:
        super().__init__(reason)
        self.reason = reason
        self.category = category
