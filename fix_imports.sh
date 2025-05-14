#!/bin/bash
# Script to fix import paths in the subfinder project
find /Users/trevor/dev/subfinder/v2 -type f -name "*.go" -exec sed -i '' 's|github.com/StratumSecurity/subfinderv2|github.com/StratumSecurity/subfinder/v2|g' {} \;
