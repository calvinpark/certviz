#!/usr/bin/env python3

from __future__ import annotations

import click
from pprint import pprint as pp

from model import *


@click.command()
@click.argument('directories', nargs=-1)
def main(directories):

    directories = list(directories) + ['.']

    crypto_objects: dict = FileHelper.get_all_crypto_objects(directories)

    X509_PUB.print_list(crypto_objects[CryptoObject.TYPE_X509_PUB])
    X509_PRV.print_list(crypto_objects[CryptoObject.TYPE_X509_PRV])
    X509_REQ.print_list(crypto_objects[CryptoObject.TYPE_X509_REQ])


if __name__ == '__main__':
    main()
