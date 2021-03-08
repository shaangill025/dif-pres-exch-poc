"""Validators for schema fields."""

import json

from datetime import datetime

from marshmallow.validate import OneOf, Range, Regexp
from marshmallow.exceptions import ValidationError
from datetime import datetime, timedelta, timezone
from typing import Union

def epoch_to_str(epoch: int) -> str:
    return datetime_to_str(datetime.fromtimestamp(epoch, tz=timezone.utc))

def datetime_to_str(dt: Union[str, datetime]) -> str:
    if isinstance(dt, datetime):
        dt = dt.replace(tzinfo=timezone.utc).isoformat(" ").replace("+00:00", "Z")
    return dt


class WholeNumber(Range):
    """Validate value as non-negative integer."""

    EXAMPLE = 0

    def __init__(self):
        """Initializer."""

        super().__init__(min=0, error="Value {input} is not a non-negative integer")

    def __call__(self, value):
        """Validate input value."""

        if type(value) != int:
            raise ValidationError("Value {input} is not a valid whole number")
        super().__call__(value)


class IndyISO8601DateTime(Regexp):
    """Validate value against ISO 8601 datetime format, indy profile."""

    EXAMPLE = epoch_to_str(int(datetime.now().timestamp()))
    PATTERN = (
        r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d"
        r"(?:\:(?:\d\d(?:\.\d{1,6})?))?(?:[+-]\d\d:?\d\d|Z|)$"
    )

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyISO8601DateTime.PATTERN,
            error="Value {input} is not a date in valid format",
        )


class Base64(Regexp):
    """Validate base64 value."""

    EXAMPLE = "ey4uLn0="
    PATTERN = r"^[a-zA-Z0-9+/]*={0,2}$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            Base64.PATTERN,
            error="Value {input} is not a valid base64 encoding",
        )


class UUIDFour(Regexp):
    """Validate UUID4: 8-4-4-4-12 hex digits, the 13th of which being 4."""

    EXAMPLE = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
    PATTERN = (
        r"[a-fA-F0-9]{8}-"
        r"[a-fA-F0-9]{4}-"
        r"4[a-fA-F0-9]{3}-"
        r"[a-fA-F0-9]{4}-"
        r"[a-fA-F0-9]{12}"
    )

    def __init__(self):
        """Initializer."""

        super().__init__(
            UUIDFour.PATTERN,
            error="Value {input} is not UUID4 (8-4-4-4-12 hex digits with digit#13=4)",
        )


# Instances for marshmallow schema specification
WHOLE_NUM = {"validate": WholeNumber(), "example": WholeNumber.EXAMPLE}
INDY_ISO8601_DATETIME = {
    "validate": IndyISO8601DateTime(),
    "example": IndyISO8601DateTime.EXAMPLE,
}
BASE64 = {"validate": Base64(), "example": Base64.EXAMPLE}
UUID4 = {"validate": UUIDFour(), "example": UUIDFour.EXAMPLE}
