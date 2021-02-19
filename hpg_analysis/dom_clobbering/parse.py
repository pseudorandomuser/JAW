import os
import re
import sys
import json
import math
import subprocess


SITE_ID_MIN = 1
SITE_ID_MAX = 150
REQUIRED_VALID = 20
SCRIPT_SIZE_MIN = 100_000
SCRIPT_SIZE_MAX = 10_000_000
CONSTRAINT_SIZE = True
CONSTRAINT_WINDOW = True

PROJECT_ROOT = os.path.join(os.path.dirname(sys.argv[0]), f'..{os.path.sep}..')
CLOBBER_ROOT = os.path.join(PROJECT_ROOT, f'hpg_analysis{os.path.sep}dom_clobbering')
CLOBBER_DATA = os.path.join(PROJECT_ROOT, f'hpg_construction{os.path.sep}outputs')


def prevalidate_constraints(program_path):

    if not os.path.isfile(program_path):
        return False

    constraints = True

    if not CONSTRAINT_SIZE and not CONSTRAINT_WINDOW:
        return constraints

    if CONSTRAINT_SIZE:
        file_size = os.path.getsize(program_path)
        constraints = constraints and file_size > SCRIPT_SIZE_MIN and file_size < SCRIPT_SIZE_MAX
    
    if CONSTRAINT_WINDOW:
        with open(program_path, 'r') as file_handle:
            window_regex = re.compile('window\.')
            file_content = file_handle.read()
            constraints = constraints and window_regex.search(file_content) != None

    return constraints

def parse_js(program_path):
    node_proc = subprocess.Popen(['node', os.path.join(CLOBBER_ROOT, 'parse.js'), program_path])
    node_proc.wait()
    return node_proc.returncode == 0

def get_progress_bar(current, max, width=20, unit=''):
    running_chars = ['|', '/', '-', '\\']
    running_char = running_chars[current % len(running_chars)] if current < max else '✔'
    progress = math.ceil((current / max) * width)
    return f"[{progress * '#'}{(width - progress) * ' '}] {running_char} ({current}{unit}/{max}{unit})"

def get_fancy_progress_bar(current, max, width=20, unit=''):
    item_char = '•'
    pacman_chars = ['ᗧ', '○']
    pacman_char = pacman_chars[current % len(pacman_chars)]
    running_chars = ['|', '/', '-', '\\']
    running_char = running_chars[current % len(running_chars)] if current < max else '✔'
    progress = math.ceil((current / max) * width)
    progress_chars = f"{(progress - 1) * ' '}{pacman_char}{(width - progress) * item_char}" if current < max else width * '#'
    return f"[{progress_chars}] {running_char} ({current}{unit}/{max}{unit})"


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

                if prevalidate_constraints(url_prog) and parse_js(url_prog):
                    parsable_urls.append(url_hash)

                valid_count = len(parsable_urls)
                invalid_count = current_index + 1 - valid_count
                progress_bar = get_fancy_progress_bar(current_index + 1, site_urls_count, width=40)
                print(f'{progress_bar} ({valid_count} OK, {invalid_count} FAIL)', end='\r', flush=True)

        except KeyboardInterrupt:
            parsing_interrupted = True
            print('\nUser interrupted parsing process!', end='', flush=True)

        if len(parsable_urls) >= REQUIRED_VALID:
            parsable_sites[str(site_id)] = parsable_urls

        if parsing_interrupted: break

    result = json.dumps(parsable_sites, indent=4)

    result_path = os.path.join(CLOBBER_ROOT, 'parse.json')
    file_handle = open(result_path, 'w')
    file_handle.write(result)
    file_handle.close()

    print(f'\n\n{result}')