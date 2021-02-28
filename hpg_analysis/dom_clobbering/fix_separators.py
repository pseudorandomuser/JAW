import os
import sys
import shutil
import argparse

import constants

SEPARATOR_CHAR = '\xbf'
REPLACEMT_CHAR = ''

if __name__ == '__main__':

    main_parser = argparse.ArgumentParser(description='Tool for replacing CSV separator characters in JavaScript')
    main_parser.add_argument('--id',  metavar='id', type=int, help='ID of the website to replace the separator character in', required=True)
    args = main_parser.parse_args()

    site_id = str(args.id)
    site_path = os.path.join(constants.CLOBBER_DATA, site_id)

    if not os.path.isdir(site_path):
        print(f'Invalid site ID {site_id}!')
        sys.exit(-1)

    url_hashes = [ dir for dir in os.listdir(site_path) if os.path.isdir(os.path.join(site_path, dir)) ]

    for url_hash in url_hashes:

        url_path = os.path.join(site_path, url_hash)
        url_prog = os.path.join(url_path, 'js_program.js')

        if not os.path.isfile(url_prog):
            print(f'ID {site_id} URL {url_hash} is missing JavaScript, skipping...')
            continue

        script_handle = open(url_prog, 'r')
        script_contents = script_handle.read()
        script_handle.close()

        if not SEPARATOR_CHAR in script_contents:
            print(f'ID {site_id} URL {url_hash} does not contain separator, skipping...')
            continue

        url_prog_backup = f'{url_prog}.orig'
        if not os.path.isfile(url_prog_backup):
            print(f'ID {site_id} URL {url_hash} no existing backup, creating new one...')
            shutil.copy2(url_prog, url_prog_backup)
        
        script_handle = open(url_prog, 'w')
        script_handle.write(script_contents.replace(SEPARATOR_CHAR, REPLACEMT_CHAR))
        script_handle.flush()
        script_handle.close()

        print(f'ID {site_id} URL {url_hash} removed separator characters!')