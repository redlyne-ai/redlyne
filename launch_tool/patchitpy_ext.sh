#!/bin/bash



# ----------     SET SRC DIRECTORY      ----------
# Check input argument
if [ -z "$1" ]; then
    echo "Usage: $0 <path1>"
    exit 1
fi
if [ -z "$2" ]; then
    echo "Usage: $0 $1 <path2>"
    exit 1
fi

# Extract file name
filename=$(basename "$1")
nameWithoutType=$(echo "$filename" | awk -F '.' '{print $1}')

# Extract the path
SRC_DIR=$(dirname "$1")

# Set installation path of the tool 
TOOL_DIR="$2"

RES_DIR="$SRC_DIR/results_$nameWithoutType"

SCRIPT_DIR="$TOOL_DIR/script_py"
GEN_DIR="$TOOL_DIR/generated_file"

PATH_1="/opt/homebrew/opt/grep/libexec/gnubin"
PATH_2="/usr/local/opt/grep/libexec/gnubin"

name_os=$(uname)
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")

# ----------     CREATE RESULTS DIRECTORIES      ----------
dirs=("$RES_DIR")
for dir in "${dirs[@]}"; do
    # Crea la cartella, incluso il percorso intermedio
    mkdir -p "$dir"
    if [ $? -eq 0 ]; then
        echo "Created directory: $dir"
    else
        echo "Failed to create directory: $dir"
    fi
done

echo "$1" | grep -q "/"
if [ $? -eq 0 ]; then
    new_name="$filename"
else
    new_name="$1"
fi

filename_res="[$timestamp]_$new_name"
type=$(echo "$filename_res" | awk -F '.' '{print $2}')

echo "$1" | grep -q ".txt"
if [ $? -eq 1 ]; then
    filename_res=$(echo "$filename_res" | sed "s/.$type/.txt/g")
fi

# Define the names of the generated files
rem_file="REM_$filename_res"
input_file="INPUT_$filename_res"
tmp_file="MOD_INPUT_$filename_res"

# Define the paths of the generated files
rem_path="$RES_DIR/$rem_file"
input_path="$GEN_DIR/$input_file"
tmp_path="$GEN_DIR/$tmp_file"

# ----------     CONVERTING JSON TO TXT      ----------
if [ "$type" == "json" ]; then
    cat "$1" | grep -q "\"code\":"
    if [ $? -eq 0 ]; then
        python3 "$SCRIPT_DIR/convert_json_to_txt.py" "$1" "$tmp_path"
    else
        python3 "$SCRIPT_DIR/convert_json_wo_keys.py" "$1" "$tmp_path"
    fi
fi

# ----------      SETUP       ----------
if [ "$name_os" = "Darwin" ]; then  # MAC-OS system

    ls "$PATH_1" > /dev/null 2>&1
    if [ $? -eq 0 ]; then   # If the path already exists, it is not exported
        echo "$PATH" | grep -q "$PATH_1"
        if [ $? -eq 1 ]; then
            export "PATH=$PATH_1:$PATH"
        fi
    else
        ls "$PATH_2" > /dev/null 2>&1
        if [ $? -eq 0 ]; then   # If the path already exists, it is not exported
            echo "$PATH" | grep -q "$PATH_2"
            if [ $? -eq 1 ]; then
                export "PATH=$PATH_2:$PATH"
            fi
        fi
    fi
    if [ "$type" == "json" ]; then
        python3 "$SCRIPT_DIR/preprocessing_macos.py" "$tmp_path" "$input_path"
        rm "$tmp_path"
    elif [ "$type" == "txt" ]; then
        python3 "$SCRIPT_DIR/preprocessing_macos.py" "$1" "$input_path"
    fi

elif [ "$name_os" = "Linux" ]; then  # LINUX system
    if [ "$type" == "json" ]; then
        python3 "$SCRIPT_DIR/preprocessing.py" "$tmp_path" "$input_path"
        rm "$tmp_path"
    elif [ "$type" == "txt" ]; then
        python3 "$SCRIPT_DIR/preprocessing.py" "$1" "$input_path"
    fi
fi

# ----------     LAUNCHING THE TOOL     ----------
echo -e "[***] Vulnerability Scanning ...\n"

bash "$TOOL_DIR/tool_derem_ext.sh" "$input_path" "$rem_path" 2> /dev/null
