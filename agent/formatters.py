"""Module exposing functionalities to format technical details of the findings before emitting them."""
from typing import Any, Callable


TRUNCATE_SIZE = 256


def truncate_str(value: str | bytes, truncate_size: int = TRUNCATE_SIZE) -> str:
    """Truncate a string or bytes value.

    Args:
        value: the string or bytes value.
        truncate_size: how much to truncate.

    Returns:
        the truncated string or bytes value.
    """
    if isinstance(value, (str, bytes)):
        if len(value) > truncate_size:
            value = f"{str(value)[:truncate_size]}..."
        else:
            value = str(value)
    return value


def minify_dict(
    value: Any,
    handler: Callable[[str | bytes, int], str],
    truncate_size: int = TRUNCATE_SIZE,
) -> dict[object, object] | list[object] | object:
    """Recursive approach to minify dictionary values.

    Args:
        dic: The dictionary to minify.
        handler: Method that will be applied to all the values.

    Returns:
        the minified version of the dict.
    """
    if isinstance(value, list):
        return [minify_dict(v, handler) for v in value]
    elif isinstance(value, dict):
        for key, v in value.items():
            value[key] = minify_dict(v, handler)
        return value
    else:
        return handler(value, truncate_size)
