import os
import sys
import random
import subprocess

from .const import CLOBBER_DATA, CLOBBER_ROOT, PROJECT_ROOT
from .main import run_analysis, import_site_data

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <site_id>')
        sys.exit(-1)
    
    site_id = sys.argv[1]
    site_path = os.path.join(CLOBBER_DATA, site_id)

    if os.path.isdir(site_path):
        print(f'Analyzing URLs for site ID: {site_id}')

        reports_path = os.path.join(CLOBBER_ROOT, 'reports')
        report_path = os.path.join(reports_path, site_id)

        if not os.path.isdir(report_path):
            os.makedirs(report_path)

        url_hashes = [ dir for dir in os.listdir(site_path) if os.path.isdir(os.path.join(site_path, dir)) and f'{dir}.txt' not in os.listdir(report_path) ]

        for i in range(0, min(len(url_hashes), 20)):

            url_hash = random.choice(url_hashes)
            url_hashes.remove(url_hash)
            url_report_path = os.path.join(report_path, f'{url_hash}.txt')

            print(f'Importing URL with hash {url_hash}...')
            import_site_data(site_id=int(site_id), url_id=url_hash, overwrite=True)

            print(f'Analyzing URL with hash {url_hash}...')
            run_analysis(url_report_path, True)

            print(f'Report saved to {url_report_path}!')

    else:
        print(f'Invalid site ID: {site_id}')
        sys.exit(-2)