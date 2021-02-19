import os
import re
import sys
import json
import math
import subprocess


SITE_ID_MIN = 11
SITE_ID_MAX = 15
REQUIRED_VALID = 1

PROJECT_ROOT = os.path.join(os.path.dirname(sys.argv[0]), f'..{os.path.sep}..')
CLOBBER_ROOT = os.path.join(PROJECT_ROOT, f'hpg_analysis{os.path.sep}dom_clobbering')
CLOBBER_DATA = os.path.join(PROJECT_ROOT, f'hpg_construction{os.path.sep}outputs')


def parse_js(program_path):
    node_proc = subprocess.Popen(['node', os.path.join(CLOBBER_ROOT, 'parse.js'), program_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    node_proc.wait()
    return node_proc.returncode == 0

def get_progress_bar(current, max, width=20):
    progress = math.ceil((current / max) * width)
    return '[' + (progress * '#') + ((width - progress) * ' ') + ']'


if __name__ == '__main__':
    
    parsable_sites = {}

    os.system('clear')

    print(f'Verifying JavaScript snippets from site IDs {SITE_ID_MIN} to {SITE_ID_MAX}...')

    for site_id in range(SITE_ID_MIN, SITE_ID_MAX + 1):

        parsing_interrupted = False

        print(f'\nAttempting to parse JavaScript from URLs of site with ID {site_id}... ', flush=True)

        site_path = os.path.join(CLOBBER_DATA, str(site_id))

        if not os.path.isdir(site_path):
            print(f'Site with ID {site_id} does not exist, skipping...', end='', flush=True)
            continue

        site_urls = [ dir for dir in os.listdir(site_path) if os.path.isdir(os.path.join(site_path, dir)) ]
        site_urls_count = len(site_urls)

        parsable_urls = []

        try:

            for current_index in range(0, site_urls_count):

                url_hash = site_urls[current_index]
                url_path = os.path.join(site_path, url_hash)
                url_prog = os.path.join(url_path, 'js_program.js')

                if parse_js(url_prog):
                    parsable_urls.append(url_hash)

                progress_bar = get_progress_bar(current_index + 1, site_urls_count, width=40)
                valid_count = len(parsable_urls)
                invalid_count = current_index + 1 - valid_count
                print(f'{progress_bar} ({current_index + 1}/{site_urls_count}) ({valid_count} OK, {invalid_count} FAIL)', end='\r', flush=True)

        except KeyboardInterrupt:
            parsing_interrupted = True
            print('\nUser interrupted parsing process!', end='', flush=True)

        if len(parsable_urls) >= REQUIRED_VALID:
            parsable_sites[str(site_id)] = parsable_urls

        if parsing_interrupted: break

    result = json.dumps(parsable_sites, indent=4)

    result_path = os.path.join(CLOBBER_ROOT, 'parsable.txt')
    file_handle = open(result_path, 'w')
    file_handle.write(result)
    file_handle.close()

    print(f'\n\n{result}')