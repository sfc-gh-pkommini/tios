import re
from datetime import datetime, timedelta
from typing import Tuple, Any


def get_timestamps(days: int) -> Tuple[datetime, datetime]:
    from_date = datetime.today() - timedelta(days=days)
    to_date = datetime.today()

    from_ts = datetime.combine(from_date, datetime.min.time())  # type: ignore
    to_ts = datetime.combine(to_date, datetime.min.time())  # type: ignore
    return from_ts, to_ts


def contains_malicious_chars(s: str) -> bool:
    p = re.compile("[^a-zA-Z0-9\-_]")
    m = p.search(s)
    return m is not None


def get_offset(page_size: int, page_number: int):
    return page_size * page_number
