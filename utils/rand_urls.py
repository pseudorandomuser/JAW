#!/usr/bin/env python3

import os
import sys
import random

MAX_ITEMS = 20
ROOT_DIR = os.path.join(os.path.dirname(sys.argv[0]), '..')
DATA_DIR = os.path.join(ROOT_DIR, f"hpg_construction{os.path.sep}outputs")

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Usage: %s <site_id>' % sys.argv[0])
		sys.exit(-1)
	base_dir = os.path.join(DATA_DIR, sys.argv[1])
	if not os.path.isdir(base_dir):
		print('%s is not a valid directory!' % base_dir)
		sys.exit(-2)
	dir_contents = [dir for dir in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, dir))]
	dir_count = len(dir_contents)
	num_items = min(dir_count, MAX_ITEMS)
	available_index = [i for i in range(0, dir_count)]
	for i in range(0, num_items):
		index = random.choice(available_index)
		available_index.remove(index)
		dir_name = dir_contents[index]
		print('%d.\t%s' % (i + 1, dir_name))
	if num_items < MAX_ITEMS:
		print('WARNING: Less items (%d) were printed than expected (%d)!' % (num_items, MAX_ITEMS))
