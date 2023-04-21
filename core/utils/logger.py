import logging
from rich.logging import RichHandler


class MyLogger(logging.Logger):
    def __init__(self, name):
        super().__init__(name)
        handler = RichHandler()
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        self.addHandler(handler)
        self.setLevel(logging.DEBUG)
