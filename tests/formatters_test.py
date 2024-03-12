"""Unit test for the findings formatters."""

from pytest_mock import plugin

from agent import formatters


def testTruncate_always_shouldTruncateString() -> None:
    """Ensure the truncate formatter returns the correct number of characters & adds `...` at the end."""
    long_string = "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium"

    truncated = formatters.truncate(long_string, truncate_size=20)

    assert truncated == "Sed ut perspiciatis ..."


def testMinifyDict_whenSimpleDict_shouldMinifyStringValues(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the minify dict method return correct values for a simple dictionary."""
    # Mock the default value of the truncate method, and set it to a small number.
    mocker.patch.object(formatters.minify_dict, "__defaults__", (5,))

    input_dict = {
        "key1": "very long string value.....",
        "key2": "another very long string value.....",
        "key3": "a third very long string value.....",
    }
    minified_dict = formatters.minify_dict(input_dict, formatters.truncate)

    assert minified_dict == {
        "key1": "very ...",
        "key2": "anoth...",
        "key3": "a thi...",
    }


def testMinifyDict_whenNestedDict_shouldMinifyStringValues(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the minify dict method return correct values for nested dictionaries."""
    mocker.patch.object(formatters.minify_dict, "__defaults__", (2,))
    input_dict = {
        "key1": "very long string value.....",
        "key2": {"key3": {"key4": "key4 very long string value...."}, "key5": 5},
        "key6": "a third very long string value.....",
    }

    minified_dict = formatters.minify_dict(input_dict, formatters.truncate)

    assert minified_dict == {
        "key1": "ve...",
        "key2": {"key3": {"key4": "ke..."}, "key5": 5},
        "key6": "a ...",
    }


def testMinifyDict_whenNestedDictsAndList_shouldMinifyStringValues(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the minify dict method return correct values for nested dictionaries and lists."""
    mocker.patch.object(formatters.minify_dict, "__defaults__", (3,))
    input_dict = {
        "key1": "very long string value.....",
        "key2": {
            "key3": {
                "listValues": [
                    {"key4": "key4 very long string value...."},
                    {"key6": 42},
                ]
            },
            "key5": 42,
        },
    }
    minified_dict = formatters.minify_dict(input_dict, formatters.truncate)

    assert minified_dict == {
        "key1": "ver...",
        "key2": {
            "key3": {
                "listValues": [
                    {"key4": "key..."},
                    {"key6": 42},
                ]
            },
            "key5": 42,
        },
    }
