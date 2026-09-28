import sys

from app import create_app

if __name__ == "__main__":
    print(open(sys.argv[1]).read())
    create_app().run()
