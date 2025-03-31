#!/bin/bash

# Loop over all .tar.gz files in the current directory
for file in *.tar.gz; do
  # Extract the base name without extension (removes .tar.gz)
  base=$(basename "$file" .tar.gz)
  
  # Extract the number part from the filename (assuming it's a number)
  number=$(echo "$base" | grep -oE '[0-9]+')
  
  # Extract the tar.gz file
  tar xzf "$file"

  base="${base%_*}"
  
  # Move the extracted directory (assuming it's named the same as the base)
  if [ -d "$base" ]; then
    mv "$base" "${base}_${number}"
  else
    echo "Directory $base not found"
  fi
done

# useful command
# grep -rl 'your_sentence' . | xargs rm