#!/bin/bash

JAW_ROOT="$(dirname "$0")/../.."
SITE_ID=$1

docker run --name JAW_$SITE_ID \
	--env SITE_ID=$SITE_ID \
	-v $JAW_ROOT/hpg_analysis/dom_clobbering/reports:/reports \
	-v $JAW_ROOT/hpg_construction/outputs:/outputs \
	-it v8bigblock/jaw_analysis