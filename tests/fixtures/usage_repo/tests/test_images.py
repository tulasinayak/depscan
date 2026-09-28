from PIL import Image


def test_open(tmp_path):
    Image.open(tmp_path / "x.png")
