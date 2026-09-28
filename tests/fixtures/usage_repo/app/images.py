from PIL import Image as Img
import PIL.ImageMath


def thumb(path):
    im = Img.open(path)
    im.thumbnail((64, 64))
    return PIL.ImageMath.eval("a + 1", a=im)
