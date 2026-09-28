import zipfile

import zipp


def list_members(stream):
    with zipfile.ZipFile(stream) as archive:
        return sorted(archive.namelist())
    return sorted(p.name for p in zipp.Path(zipfile.ZipFile(stream)).iterdir())
