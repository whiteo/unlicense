import ctypes
import logging
import sys

import lief

ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
STD_OUTPUT_HANDLE = -11


def setup_logger(logger: logging.Logger, verbose: bool) -> None:
    lief.logging.disable()
    if verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logger.setLevel(log_level)

    # Create a console handler with a higher log level
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)

    stream_handler.setFormatter(CustomFormatter(_console_supports_color()))

    logger.addHandler(stream_handler)


def _console_supports_color() -> bool:
    if not sys.stdout.isatty():
        return False

    # Legacy conhost prints raw escape sequences unless VT100 is enabled
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0:
            return True
        return bool(
            kernel32.SetConsoleMode(
                handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except (AttributeError, OSError):
        return False


class CustomFormatter(logging.Formatter):

    def __init__(self, use_color: bool = True) -> None:
        super().__init__()

        grey = "\x1b[38;20m" if use_color else ""
        green = "\x1b[1;32m" if use_color else ""
        yellow = "\x1b[33;20m" if use_color else ""
        red = "\x1b[31;20m" if use_color else ""
        bold_red = "\x1b[31;1m" if use_color else ""
        reset = "\x1b[0m" if use_color else ""
        format_problem_str = "%(levelname)s - %(message)s"

        formats = {
            logging.DEBUG: grey + "%(levelname)s - %(message)s" + reset,
            logging.INFO: green + "%(levelname)s" + reset + " - %(message)s",
            logging.WARNING: yellow + format_problem_str + reset,
            logging.ERROR: red + format_problem_str + reset,
            logging.CRITICAL: bold_red + format_problem_str + reset
        }
        self._formatters = {
            level: logging.Formatter(fmt)
            for level, fmt in formats.items()
        }

    def format(self, record: logging.LogRecord) -> str:
        formatter = self._formatters.get(record.levelno)
        if formatter is None:
            return super().format(record)
        return formatter.format(record)
