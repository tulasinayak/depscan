import importlib

mod = importlib.import_module("yaml")


def parse(text):
    return mod.safe_load(text)
