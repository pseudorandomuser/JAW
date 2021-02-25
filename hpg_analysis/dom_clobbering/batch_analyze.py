import os
import sys
import json
import time
import random
import subprocess

from .main import run_analysis

import constants
from hpg_neo4j.db_utility import API_neo4j_prepare

from neo4j.exceptions import ServiceUnavailable


NUM_ANALYZE_URLS = 22
MAX_RETRIES = 3
FAIL_DELAY = 10


def graph_import(site_id, url_hash):

    site_path = os.path.join(constants.CLOBBER_DATA, site_id)
    url_path = os.path.join(site_path, url_hash)

    node_path = os.path.join(url_path, constants.NODE_INPUT_FILE_NAME)
    rels_path = os.path.join(url_path, constants.RELS_INPUT_FILE_NAME)

    if not os.path.isfile(node_path) or not os.path.isfile(rels_path):
        return False

    API_neo4j_prepare(url_path)
    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <site_id>')
        sys.exit(-1)
    
    site_id = sys.argv[1]
    site_path = os.path.join(constants.CLOBBER_DATA, site_id)

    if os.path.isdir(site_path):
        print(f'Analyzing URLs for site ID: {site_id}')

        reports_path = os.path.join(constants.CLOBBER_ROOT, 'reports')
        report_path = os.path.join(reports_path, site_id)

        if not os.path.isdir(report_path):
            os.makedirs(report_path)

        #url_hashes = [ dir for dir in os.listdir(site_path) if os.path.isdir(os.path.join(site_path, dir)) and f'{dir}.txt' not in os.listdir(report_path) ]

        parse_path = os.path.join(constants.CLOBBER_ROOT, 'parse.json')
        parse_handle = open(parse_path, 'r')
        parse_dict = json.load(parse_handle)
        parse_handle.close()

        if not site_id in parse_dict:
            print(f'Site with ID {site_id} is not in the allowed set.')
            sys.exit(-2)

        url_hashes = parse_dict[site_id]

        num_analyze = 0

        while len(url_hashes) > 0 and num_analyze < NUM_ANALYZE_URLS:

            url_hash = random.choice(url_hashes)
            url_hashes.remove(url_hash)
            url_report_path = os.path.join(report_path, f'{url_hash}.txt')

            print(f'Importing URL with hash {url_hash}...')
            if not graph_import(site_id, url_hash):
                print('Import failed, skipping...')
                continue

            print(f'Analyzing URL with hash {url_hash}...')

            num_retries = 0
            while num_retries < MAX_RETRIES:
                try:
                    run_analysis(url_report_path, True)
                    num_analyze += 1
                    break
                except ServiceUnavailable, err:
                    print(f'Analysis failed, retrying... {num_retries+1}/{MAX_RETRIES}')
                    time.sleep(FAIL_DELAY)
                    num_retries += 1

            print(f'Report saved to {url_report_path}!')

    else:
        print(f'Invalid site ID: {site_id}')
        sys.exit(-2)