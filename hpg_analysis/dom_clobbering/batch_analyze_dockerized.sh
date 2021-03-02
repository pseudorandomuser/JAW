#!/bin/bash

MEMORY=8G
MEMORY_SWAP=16G

SITE_ID=$1
JAW_ROOT="$(dirname "$0")/../.."

docker run --name JAW_$SITE_ID \
	--env SITE_ID=$SITE_ID \
    --memory=$MEMORY \
	--memory-swap=$MEMORY_SWAP \
	-v $JAW_ROOT/hpg_analysis/dom_clobbering/reports:/reports \
	-v $JAW_ROOT/hpg_analysis/dom_clobbering/logs:/var/log/neo4j \
	-v $JAW_ROOT/hpg_construction/outputs:/outputs \
	--rm -it v8bigblock/jaw_analysis