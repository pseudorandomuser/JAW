#!/bin/bash

brew install ./neo4j.rb
brew pin neo4j
rmdir /usr/local/Cellar/neo4j/3.5.9/libexec/data/databases
ln -s /usr/local/var/neo4j/data/databases /usr/local/Cellar/neo4j/3.5.9/libexec/data/databases
