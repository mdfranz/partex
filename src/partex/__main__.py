"""Command-line entry point for Partex."""

import argparse
from importlib.metadata import version


def main() -> None:
    """Parse the command line."""
    parser = argparse.ArgumentParser(prog='partex')
    parser.add_argument('--version', action='version', version=f'partex {version("partex")}')
    parser.parse_args()


if __name__ == '__main__':
    main()
