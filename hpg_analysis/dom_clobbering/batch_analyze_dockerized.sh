#!/bin/bash

SITE_ID=$1
CPUS=2
MEMORY=4G
MEMORY_SWAP=4G

JAW_ROOT="$(dirname "$0")/../.."
docker run --name "JAW_$SITE_ID" \
	--env SITE_ID="$SITE_ID" \
	--cpus="$CPUS" \
    --memory="$MEMORY" \
	--memory-swap="$MEMORY_SWAP" \
	-v "$JAW_ROOT/hpg_analysis/dom_clobbering/reports:/reports" \
	-v "$JAW_ROOT/hpg_analysis/dom_clobbering/logs/$SITE_ID:/var/log/neo4j" \
	-v "$JAW_ROOT/hpg_construction/outputs:/outputs" \
	--rm -it v8bigblock/jaw_analysis