import os
import re
import sys
import ast
import json
import math


PROJECT_ROOT = os.path.join(os.path.dirname(sys.argv[0]), f'..{os.path.sep}..')
CLOBBER_ROOT = os.path.join(PROJECT_ROOT, f'hpg_analysis{os.path.sep}dom_clobbering')
CLOBBER_DATA = os.path.join(PROJECT_ROOT, f'hpg_construction{os.path.sep}outputs')


if __name__ == '__main__':

    parsable_path = os.path.join(CLOBBER_ROOT, 'parse.json')
    parsable_handle = open(parsable_path, 'r')
    parsable_dict = json.load(parsable_handle)
    parsable_handle.close()

    categories_dict = {}
    categories_regex = re.compile('^([0-9]+)- http://(.*) - (\[.*\])')
    categories_path = os.path.join(CLOBBER_ROOT, 'categories.txt')
    categories_handle = open(categories_path, 'r')
    for line in categories_handle.readlines():
        site_id, site_domain, site_categories_str = categories_regex.match(line).groups()
        site_categories = ast.literal_eval(site_categories_str)
        categories_dict[str(site_id)] = {'domain': site_domain, 'categories': site_categories}
    categories_handle.close()

    aggregated_dict = {}

    for site_id, site_urls in parsable_dict.items():
        
        num_urls = len(site_urls)

        script_size_min = sys.maxsize
        script_size_max = 0
        script_size_all = 0

        site_urls_aggregated = []

        for site_url in site_urls:
            site_path = os.path.join(CLOBBER_DATA, site_id)
            site_url_path = os.path.join(site_path, site_url)
            site_url_prog_path = os.path.join(site_url_path, 'js_program.js')
            site_url_text_path = os.path.join(site_url_path, 'navigation_url.out')

            with open(site_url_text_path, 'r') as site_url_text_handle:
                site_url_text = site_url_text_handle.readline().strip()
                site_urls_aggregated.append({'hash': site_url, 'url': site_url_text})

            script_size = os.path.getsize(site_url_prog_path)
            script_size_max = max(script_size_max, script_size)
            script_size_min = min(script_size_min, script_size)
            script_size_all += script_size

        script_size_avg = math.floor(script_size_all / num_urls)

        aggregated_dict[site_id] = {
            'domain': categories_dict[site_id]['domain'],
            'categories': categories_dict[site_id]['categories'],
            'script_size_min': script_size_min,
            'script_size_max': script_size_max,
            'script_size_avg': script_size_avg,
            'urls_count': num_urls,
            'urls': site_urls_aggregated
        }

    aggregated_dict_sorted = { key: aggregated_dict[key] for key in 
        sorted(aggregated_dict, key=lambda x: aggregated_dict.get(x).get('script_size_avg')) }

    categories_filtered_path = os.path.join(CLOBBER_ROOT, 'categories_filtered.txt')
    categories_filtered_handle = open(categories_filtered_path, 'w')
    for site_id in aggregated_dict_sorted.keys():
        site_info = categories_dict[site_id]
        categories_filtered_handle.write(f"{site_id}- http://{site_info['domain']} - {str(site_info['categories'])}\n")

    categories_filtered_handle.flush()
    categories_filtered_handle.close()

    result = json.dumps(aggregated_dict_sorted, indent=4)

    result_path = os.path.join(CLOBBER_ROOT, 'aggregate.json')
    file_handle = open(result_path, 'w')
    file_handle.write(result)
    file_handle.close()