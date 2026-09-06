# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Failures contained at third-party tool boundaries."""

import traceback


class ShellcodeLoadError(RuntimeError):
    """A generated input that the third-party shellcode loader could not map."""

    tool = "angr.load_shellcode"

    def __init__(self, error: Exception) -> None:
        self.error_kind = type(error).__name__
        self.error_message = str(error) or repr(error)
        self.formatted_traceback = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        super().__init__(f"{self.tool} raised {self.error_kind}: {self.error_message}")
