import os
import sys
import json
import time
import psutil
import random
import logging
import subprocess

from concurrent.futures import ThreadPoolExecutor

import constants


logging.basicConfig(format='%(asctime)s %(funcName)s(): %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
LOGGER = logging.getLogger('batch_graph_construct')
LOGGER.setLevel(logging.DEBUG)


MAX_WORKERS = 32
KILL_TIMEOUT = 60
SITE_IDS = [] #old


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
    
    LOGGER.debug(f'({site_id})({url_hash}) Waiting {KILL_TIMEOUT} seconds to kill node...')
    for i in range(0, KILL_TIMEOUT):
        if graph_proc.poll() is not None:
            LOGGER.debug(f'({site_id})({url_hash}) Node is already dead, skipping timeout!')
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

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        #for site_id in SITE_IDS:
        #site_id = str(site_id)

        if (len(sys.argv) < 2):
            print(f'Usage: f{sys.argv[0]} <site_id>')
            sys.exit(-1)

        site_id = sys.argv[1]
        site_path = os.path.join(constants.CLOBBER_DATA, site_id)

        if not os.path.isdir(site_path):
            #continue
            print(f'Invalid site ID: f{site_id}')
            sys.exit(-1)

        #site_hashes = [ dir for dir in os.listdir(site_path) if os.path.isdir(os.path.join(site_path, dir)) ]

        parse_path = os.path.join(constants.CLOBBER_ROOT, 'parse.json')
        parse_handle = open(parse_path, 'r')
        parse_dict = json.load(parse_handle)
        parse_handle.close()

        if not site_id in parse_dict:
            print(f'Site with ID {site_id} is not in the allowed set.')
            sys.exit(-2)

        url_hashes = parse_dict[site_id]

        for url_hash in url_hashes:
            executor.submit(graph_construction_worker, site_id, url_hash)