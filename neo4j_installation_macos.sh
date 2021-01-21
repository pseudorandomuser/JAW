#!/bin/bash

cd "$(dirname "$0")"

brew install ./neo4j.rb
brew pin neo4j
