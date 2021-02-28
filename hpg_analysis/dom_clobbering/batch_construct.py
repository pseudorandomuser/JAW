import os
import sys
import json
import time
import psutil
import random
import logging
import argparse
import subprocess

from concurrent.futures import ThreadPoolExecutor

import constants


logging.basicConfig(format='%(asctime)s %(funcName)s(): %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
LOGGER = logging.getLogger('batch_graph_construct')
LOGGER.setLevel(logging.DEBUG)


KILL_TIMEOUT_SECS = 60


def graph_construction_worker(site_id, url_hash):

    LOGGER.debug(f'({site_id})({url_hash}) New worker spawned!')

    site_path = os.path.join(constants.CLOBBER_DATA, site_id)
    url_path = os.path.join(site_path, url_hash)
    prog_path = os.path.join(url_path, 'js_program.js')
    relative_path = f'{site_id}{os.path.sep}{url_hash}'

    graph_proc = subprocess.Popen([
        'node', '--max-old-space-size=32000', constants.ANALYZER_DRIVER_PATH, 
        '-js', prog_path, '-o', relative_path
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    for line in graph_proc.stdout:
        line_str = line.decode('UTF-8')
        LOGGER.debug(f'({site_id})({url_hash}) {line_str}')
        if '[+] code property graph analyzer finished!' in line_str:
            LOGGER.debug(f'({site_id})({url_hash}) Detected CPG finished, breaking...')
            break
    
    LOGGER.debug(f'({site_id})({url_hash}) Waiting {KILL_TIMEOUT_SECS} seconds for node to terminate...')
    for i in range(0, KILL_TIMEOUT_SECS):
        if graph_proc.poll() is not None:
            LOGGER.debug(f'({site_id})({url_hash}) Node is already terminated, skipping timeout!')
            break
        time.sleep(1)

    if graph_proc.poll() is None:
        LOGGER.debug(f'({site_id})({url_hash}) Node still running after timeout, killing {graph_proc.pid}...')
        kill_proc = psutil.Process(graph_proc.pid)
        for subproc in kill_proc.children(recursive=True):
            subproc.kill()
        kill_proc.kill()

    graph_proc.wait()

    LOGGER.debug(f'({site_id})({url_hash}) Worker finished!')


if __name__ == '__main__':

    main_parser = argparse.ArgumentParser(description='Multithreaded Hybrid Property Graph Constructor')
    main_parser.add_argument('--id',  metavar='id', type=int, help='ID of the website to construct graphs for', required=True)
    main_parser.add_argument('--workers',  metavar='workers', type=int, help='ID of the website to construct graphs for', default=8)
    args = main_parser.parse_args()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:

        site_id = str(args.id)
        site_path = os.path.join(constants.CLOBBER_DATA, site_id)

        if not os.path.isdir(site_path):
            print(f'Invalid site ID: f{site_id}')
            sys.exit(-1)

        parse_path = os.path.join(constants.CLOBBER_ROOT, 'parse.json')
        parse_handle = open(parse_path, 'r')
        parse_dict = json.load(parse_handle)
        parse_handle.close()

        if not site_id in parse_dict:
            print(f'Site with ID {site_id} is not in the allowed set.')
            sys.exit(-2)

        url_hashes = parse_dict[site_id]

        for url_hash in url_hashes:

            url_path = os.path.join(site_path, url_hash)
            prog_path = os.path.join(url_path, 'js_program.js')

            if os.path.isfile(prog_path):
                executor.submit(graph_construction_worker, site_id, url_hash)
            else:
                print(f'({site_id})({url_hash}) JavaScript does not exist, skipping!')