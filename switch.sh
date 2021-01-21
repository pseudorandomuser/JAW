#!/bin/bash

cd "$(dirname "$0")"

python3 -m hpg_construction.api --js=test.js "/Users/admin/Documents/University/Semesters/2020_WS/CySecProject/JAW/hpg_construction/outputs/dom_clobbering/examples/$1"