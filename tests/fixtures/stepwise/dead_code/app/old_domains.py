import idna


def to_ascii(name):
    return idna.encode(name).decode("ascii")
