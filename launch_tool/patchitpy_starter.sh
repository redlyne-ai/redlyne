#!/bin/bash
# Check input argument $1 and $2
if [ -z "$1" ]; then
    echo "Usage: $0 <path1>"
    exit 1
fi
if [ -z "$2" ]; then
    echo "Usage: $0 $1 <path2>"
    exit 1
fi

echo "STARTING TOOL"

# Extract file name
filename=$(basename "$1")
nameWithoutType=$(echo "$filename" | awk -F '.' '{print $1}')

# Extract the path
SRC_DIR=$(dirname "$1")

txtFile="$nameWithoutType.txt"
txtFilePath="$SRC_DIR/$txtFile"

# Set installation path of the tool 
TOOL_DIR="$2"
SCRIPT_DIR="$TOOL_DIR/script_py"
PATCHITPY_SCRIPT_PATH="$TOOL_DIR/patchitpy_ext.sh"

echo "PATCHITPY_SCRIPT_PATH: $TOOL_DIR"

# Ensure paths with spaces are handled by wrapping them in quotes
python3 "$SCRIPT_DIR/convertInline.py" "$1" "$txtFilePath"
bash "$PATCHITPY_SCRIPT_PATH" "$txtFilePath" "$TOOL_DIR"

# Clean up
echo "Cleaning up..."
rm -f "$txtFilePath"
rm -f "$TOOL_DIR/generated_file"/*.txt

