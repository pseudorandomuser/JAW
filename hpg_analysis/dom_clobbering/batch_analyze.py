import os
import sys
import json
import time
import random
import argparse
import traceback
import importlib
import subprocess

from multiprocessing import Process

import constants

from hpg_neo4j.db_utility import API_neo4j_prepare
from hpg_analysis.dom_clobbering.main import run_analysis

from neo4j.exceptions import ServiceUnavailable


NUM_ANALYZE_URLS = 22
MAX_RETRIES = 1
FAIL_DELAY = 10


def graph_import(site_id, url_hash):

    site_path = os.path.join(constants.CLOBBER_DATA, site_id)
    url_path = os.path.join(site_path, url_hash)

    node_path = os.path.join(url_path, constants.NODE_INPUT_FILE_NAME)
    rels_path = os.path.join(url_path, constants.RELS_INPUT_FILE_NAME)

    if not os.path.isfile(node_path) or not os.path.isfile(rels_path):
        print(f'Nodes or relations missing for site {site_id} URL {url_hash}!')
        return False

    # FIXME: Multiple calls to API_neo4j_prepare in same process
    #   => "Failed to read from defunct connection"
    # Solution: Run import routine in separate processes

    import_proc = Process(target=API_neo4j_prepare, args=(url_path,))
    import_proc.start()
    import_proc.join()

    return True


if __name__ == '__main__':

    main_parser = argparse.ArgumentParser(description='Batch Hybrid Property Graph Analyzer')
    main_parser.add_argument('--id',  metavar='id', type=int, help='ID of the website to analyze', required=True)
    args = main_parser.parse_args()
    
    site_id = str(args.id)
    site_path = os.path.join(constants.CLOBBER_DATA, site_id)

    if os.path.isdir(site_path):
        print(f'Analyzing URLs for site ID: {site_id}')

        reports_path = os.path.join(constants.CLOBBER_ROOT, 'reports')
        site_reports_path = os.path.join(reports_path, site_id)

        if not os.path.isdir(site_reports_path):
            os.makedirs(site_reports_path)

        parse_path = os.path.join(constants.CLOBBER_ROOT, 'parse.json')
        parse_handle = open(parse_path, 'r')
        parse_dict = json.load(parse_handle)
        parse_handle.close()

        if not site_id in parse_dict:
            print(f'Site with ID {site_id} is not in the allowed set.')
            sys.exit(-2)

        url_hashes = [ hash for hash in parse_dict[site_id] if not
            os.path.isfile(os.path.join(site_reports_path, f'{hash}.txt')) ]

        num_success = 0

        while len(url_hashes) > 0:# and num_success < NUM_ANALYZE_URLS:

            url_hash = random.choice(url_hashes)
            url_hashes.remove(url_hash)
            url_report_path = os.path.join(site_reports_path, f'{url_hash}.txt')

            print(f'Importing URL with hash {url_hash}...')
            if not graph_import(site_id, url_hash):
                print('Import failed, skipping...')
                continue

            print(f'Analyzing URL with hash {url_hash}...')

            num_retries = 0
            while num_retries < MAX_RETRIES:
                try:
                    run_analysis(url_report_path, True)
                    num_success += 1
                    break
                except:
                    traceback.print_exc()
                    print(f'Analysis failed, retrying in {FAIL_DELAY} seconds... {num_retries+1}/{MAX_RETRIES}')
                    time.sleep(FAIL_DELAY)
                    num_retries += 1

            print(f'Report saved to {url_report_path}!')

    else:
        print(f'Invalid site ID: {site_id}')
        sys.exit(-2)