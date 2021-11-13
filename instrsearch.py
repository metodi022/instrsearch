import argparse
import pathlib


def main():
    argsparser = argparse.ArgumentParser()
    argsparser.add_argument('-p', '--path', help='path to binary file', type=pathlib.Path, required=True)
    argsparser.add_argument('-s', '--search', help='instruction search pattern', type=str, required=True, nargs='+')

    args = vars(argsparser.parse_args())


if __name__ == '__main__':
    main()
