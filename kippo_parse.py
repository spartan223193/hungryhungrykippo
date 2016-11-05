#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
from hungryhungrykippo.kippoparser import KippoParser


def main():
    '''
    The main function loop for the kippo parser

    :return: None
    '''
    argparser = argparse.ArgumentParser(description="Parse kippo log files to JSON")
    argparser.add_argument('-s', '--source', metavar="Source", help='The path to the kippo log file', required=True)
    argparser.add_argument('-o', '--output', metavar="Output", help="The path to the output file", required=True)
    args = argparser.parse_args()
    kippo_parser = KippoParser()
    kippo_parser.write_kippo_json_to_file(args.source, args.output)
    print "Kippo log successfully processed into JSON."


if __name__ == '__main__':
    main()
