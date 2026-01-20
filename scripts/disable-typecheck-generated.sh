#!/bin/bash
TARGET_DIR="src/generated"

if [ ! -d "$TARGET_DIR" ]; then
  echo "Directory $TARGET_DIR does not exist."
  exit 0
fi

find "$TARGET_DIR" -name "*.ts" -type f | while read -r file; do
  if ! grep -q "// @ts-nocheck" "$file"; then
    echo "Adding @ts-nocheck to $file"
    # Create a temp file with the directive
    echo "// @ts-nocheck" > "$file.tmp"
    # Append the original content
    cat "$file" >> "$file.tmp"
    # Move back
    mv "$file.tmp" "$file"
  fi
done
