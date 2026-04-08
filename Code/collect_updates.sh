#!/usr/bin/env bash
TARGET_DIR="nvd_updates"
cd "Data"

rm -r $TARGET_DIR
mkdir $TARGET_DIR

cd "nvdcve"

output=$(git pull)
export UPDATE_MODE="true"

if echo "$output" | grep -q "Already up to date"; then
    echo "No changes"
else
    git diff --name-only HEAD@{1} HEAD | while read file; do
        file_name=$(basename "$file")
        cp "$file" "../$TARGET_DIR/$file_name" 
    done
    cd ../../
    python3 Code/collect_projects.py

fi

