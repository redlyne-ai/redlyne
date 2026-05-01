#!/bin/bash
start=$(date +%s.%N)

input=$1
outputFile=$2



# Funzione di remediation generale
function remediate_line {
    local line="$1"
    local pattern="$2"
    local replacement="$3"
    local captured_group="$4"
    local captured_argument="$5"
    local captured_var="$6"
    local pattern_not="$7"
    local changed_line="$8"


    # Logica di remediation
    #echo "Remdiating line: $line"
    #echo "Pattern: $pattern"
    #echo "Replacement: $replacement"

    remediated_line="$(echo "$line" | sed -E "s#$pattern#$replacement#g")"
    #echo "Remediated line: $remediated_line"


    replacement_upper="$(echo "$replacement" | tr '[:lower:]' '[:upper:]')" # Convert to uppercase
    changed_line="$(echo "$changed_line" | sed -E "s#$pattern#$replacement_upper#g")"  
    changed_line="$(echo "$changed_line" | sed -E "s#\\\N#\\\n#g")"  # Convert \N to \n


    query=$(echo "$captured_argument" | sed "s/=.*/= (:$captured_var)'/" | sed "s/VALUES.*/VALUES (:$captured_var)'/")

    if [[ "$replacement" == *"REPLACE_QUERY"* ]]; then
        remediated_line=$(echo "$remediated_line" | sed "s/REPLACE_QUERY/$query/")
        changed_line=$(echo "$changed_line" | sed "s/REPLACE_QUERY/$query/")

    fi
    if [[ "$replacement" == *"REPLACE_VAR"* ]]; then
        remediated_line=$(echo "$remediated_line" | sed "s#REPLACE_VAR#$captured_var#g")
        changed_line=$(echo "$changed_line" | sed "s#REPLACE_VAR#${captured_var^^}#g")  # Convert to uppercase
    fi
    if [[ "$replacement" == *"REPLACE_PATH"* ]]; then
        # estrarre path tra singoli apici
        path=$(echo "$line" | awk -F "open\\\(" '{print $2}' | cut -d'+' -f1)
        remediated_line=$(echo "$remediated_line" | sed "s#REPLACE_PATH#$path#g")
        changed_line=$(echo "$changed_line" | sed "s#REPLACE_PATH#${path^^}#g")  # Convert to uppercase
    fi
    #remediated_line=$(echo "$remediated_line" | sed "s/REPLACE_FUNCTION/$captured_group/")

    if  [[ "$replacement" == *"REPLACE_HERE_LIST"* ]]; then
        captured_group_list=$(echo "$captured_group" | sed "s/%s//g")
        captured_group_list=$(echo "$captured_group_list" | tr -cd '[:alnum:]-._/() ')
        

        #echo "Captured group list: $captured_group_list"
        # Aggiungi parentesi quadre e virgole per ottenere una lista formattata
        captured_group_list="[\"$(echo "$captured_group_list" | sed 's/  / /g; s/,/, /g; s/ /,/g')\"]"
        captured_group_list=$(echo "$captured_group_list" | sed 's/,/","/g')
        captured_group_list=$(echo "$captured_group_list" | sed "s/\"$captured_var\"/$captured_var/g")
        if [[ "$captured_group_list" != *","* ]]; then
            captured_group_list=$(echo "$captured_group_list" | sed 's/\[\"/[/; s/\"\]/]/')
        fi
        if [[ "$captured_group_list" == *","* && "$captured_group_list" != *,*,* ]]; then
            captured_group_list=$(echo "$captured_group_list" | sed 's/,\"/,/; s/\"\]/]/')
        fi
        remediated_line=$(echo "$remediated_line" | sed "s/REPLACE_HERE_LIST/$captured_group_list/")
        changed_line=$(echo "$changed_line" | sed "s/REPLACE_HERE_LIST/${captured_group_list^^}/")  # Convert to uppercase

    fi

    if  [[ "$replacement" == *"SPECIAL1"* ]]; then
        remediated_line=$(echo "$remediated_line" | sed "s#SPECIAL1#'/'#g")
        remediated_line=$(echo "$remediated_line" | sed "s#SPECIAL2#'//'#g")
        remediated_line=$(echo "$remediated_line" | sed "s#SPECIAL3#'..'#g")

        changed_line=$(echo "$changed_line" | sed "s#SPECIAL1#'/'#g")
        changed_line=$(echo "$changed_line" | sed "s#SPECIAL2#'//'#g")
        changed_line=$(echo "$changed_line" | sed "s#SPECIAL3#'..'#g")
    fi

    if  [[ "$replacement" == *"REG"* ]]; then
        remediated_line=$(echo "$remediated_line" | sed "s#REG#\"\^\[a-zA-Z0-9_-\]\+\$\"#g")
        changed_line=$(echo "$changed_line" | sed "s#REG#\"\^\[a-zA-Z0-9_-\]\+\$\"#g")

    fi

    #echo "pattern-not: $pattern_not"
    #if [[ "$line" =~ "$pattern_not" ]]; then # in this case do nothing
    if echo "$line" | grep -qE "$pattern_not"; then
        #echo "Pattern not found"
        remediated_line="$line"
        changed_line="$line"
    fi
    echo "$remediated_line CNG_LINE $changed_line"
}

# Array di configurazioni per i diversi pattern # \"path\\/\"
pattern_configs=(
    #patterns without detection rule associated

    # aggiunta a 0di NO-MATCH-COULD-GENERATE per non generare match: va introdotta un'opportuna regola di dection e va adattata la remediation
    '{"id": 0, "pattern": "(bool|float|complex)\\(([a-zA-Z0-9_]+)\\)NO-MATCH-COULD-GENERATE", "replacement": "if \\2\\.lower\\(\\) \\!= \"nan\": \\\\n \\1\\(\\2\\)", "source": "", "pattern_not": "if \\2\\.lower\\(\\)","imports": "" , "comment": "wrap the casting operation in a try-except block to catch the ValueError"}'
    
    '{"id": 1, "pattern": "if (.*) in ([a-zA-Z0-9_.\\s]+): \\\\n return (redirect|HttpResponseRedirect)\\(\\2\\)", "replacement": "allow_dom = [\\1,\"test.com\"]\\\\n if \\2 in allow_dom:\\\\n return \\3\\(\\2\\)", "source": "([a-zA-Z0-9_.]+) = urlparse\\(", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a list of allowed domains to the redirect function"}'
    '{"id": 2, "pattern": "if ([a-zA-Z0-9_.\\s]+)==([^:]*): \\\\n return (redirect|HttpResponseRedirect)\\(", "replacement": "allow_dom = [\\2,\"test.com\"]\\\\n if \\1 in allow_dom:\\\\n return \\3\\(", "source": "([a-zA-Z0-9_.]+) = urlparse\\(", "pattern_not": "allow_dom =", "imports": "" , "comment": "add a list of allowed domains to the redirect function"}'
    '{"id": 3, "pattern": "([ ]*)return (redirect|HttpResponseRedirect)\\(([a-zA-Z0-9_.]+)\\)", "replacement": "\\1parsed_url = urlparse\\(\\3\\)\\\\n\\1allow_dom = [\"insert-allowed-url-here.com\",\"test.com\"]\\\\n\\1if parsed_url\\.netloc in allow_dom and parsed_url.scheme == \"http\":\\\\n\\1    return \\2\\(\\3\\)", "source": "([a-zA-Z0-9_.]+) = urlparse\\(", "pattern_not": "allow_dom =", "imports": "from urllib.parse import urlparse" , "comment": "add a list of allowed domains to the redirect function"}'
    '{"id": 4, "pattern": "([ ]*)return flask\\.(redirect|HttpResponseRedirect)\\(([a-zA-Z0-9_.]+)\\)", "replacement": "\\1parsed_url = urlparse\\(\\3\\)\\\\n\\1allow_dom = [\"insert-allowed-url-here.com\",\"test.com\"]\\\\n\\1if parsed_url\\.netloc in allow_dom and parsed_url.scheme == \"http\":\\\\n\\1    return \\2\\(\\3\\)", "source": "([a-zA-Z0-9_.]+) = urlparse\\(", "pattern_not": "allow_dom =", "imports": "" , "comment": "add a list of allowed domains to the redirect function"}'
    '{"id": 5, "pattern": "([ ]*)return (redirect|HttpResponseRedirect)\\(([a-zA-Z0-9_.]+),([^)]+)\\)", "replacement": "\\1parsed_url = urlparse\\(\\3\\)\\\\n\\1allow_dom = [\"insert-allowed-url-here.com\",\"test.com\"]\\\\n\\1if parsed_url\\.netloc in allow_dom and parsed_url.scheme == \"http\":\\\\n\\1    return \\2\\(\\3\\,\\4)", "source": "([a-zA-Z0-9_.]+) = urlparse\\(", "pattern_not": "allow_dom =", "imports": "" , "comment": "add a list of allowed domains to the redirect function"}'
    '{"id": 6, "pattern": "=[ ]*input\\(([^)]*)\\)", "replacement": "= input\\(\\1\\)\\.strip\\(\\)", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a strip function to the input function and add a check to see if the input is valid"}'
    
    #'{"id": 7, "pattern": "([ ]*)([a-zA-Z0-9_.]+)[ ]*=[ ]*input\\(([^)]*)\\)", "replacement": "\\1\\2 = input\\(\\3\\) \\\\n \\1\\2 = \\2 if re\\.match\\(REG, \\2\\) else None", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "import re" , "comment": "add input validation to the input function"}'
    #'{"id": 8, "pattern": "([a-zA-Z0-9_.]+) = int\\(input\\(([^)]*)\\)\\)", "replacement": "\\1 = int\\(input\\(\\2\\)\\) \\\\n \\1 = \\1 if re\\.match\\(REG, \\1\\) else None \\\\n", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "import re" , "comment": "add input validation to the input function"}'
    '{"id": 7, "pattern": "NO-MATCH-COULD-GENERATE", "replacement": "\\1\\2 = input\\(\\3\\) \\\\n \\1\\2 = \\2 if re\\.match\\(REG, \\2\\) else None", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "import re" , "comment": "add input validation to the input function"}'
    '{"id": 8, "pattern": "NO-MATCH-COULD-GENERATE", "replacement": "\\1 = int\\(input\\(\\2\\)\\) \\\\n \\1 = \\1 if re\\.match\\(REG, \\1\\) else None \\\\n", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "import re" , "comment": "add input validation to the input function"}'
    
    #old-remdiation wrog
    #'{"id": 9, "pattern": "([ ]*)os\\.remove\\(([^()]*)\\)", "replacement": "\\1file_path = os\\.path\\.join\\(\"path\\/\",\\2) \\\\n\\1if os\\.path\\.isfile\\(file_path\\): \\\\n\\1    os\\.remove\\(file_path\\)", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data)", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a check to see if the file exists in a specic path before removing it"}'

    '{"id": 9, "pattern": "([ ]*)os\\.remove\\(([^()]*)\\)", "replacement": "\\1secure_path=\"secure/radix/path/\" \\\\n\\1file_path = os\\.path\\.join\\(secure_path,\\2\\) \\\\n\\1if os.path.commonprefix\\(\\(os.path.realpath\\(file_path\\),secure_path\\)\\) == secure_path: \\\\n\\1    os\\.remove\\(file_path\\)", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data)", "pattern_not": "PLACEHOLDER", "imports": "import os" , "comment": "add a check to see if the file exists in a specic path before removing it"}'
    
    #old-remdiation wrog
    #'{"id": 10, "pattern": "([a-zA-Z0-9_]+)[ ]*=[ ]*open\\(([^()+]*),([^w()]*)\\)", "replacement": "file_path = os\\.path\\.join\\(\"path\\/\",\\2\\) \\\\n if os\\.path\\.isfile\\(file_path\\): \\\\n \\1 = open\\(file_path,\\3\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a check to see if the file exists in a specif path before opening it"}'
    #'{"id": 11, "pattern": "([a-zA-Z0-9_]+)[ ]*=[ ]*open\\(([^()]*\\+[^()]*),([^w()]*)\\)", "replacement": "file_path = os\\.path\\.join\\(REPLACE_PATH,REPLACE_VAR\\) \\\\n if os\\.path\\.isfile\\(file_path\\): \\\\n \\1 = open\\(file_path,\\3\\)", "source": "\\+([a-zA-Z0-9_ ]+)", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a check to see if the file exists in a specif path before opening it"}'
    '{"id": 10, "pattern": "([ ]*)([a-zA-Z0-9_]+)[ ]*=[ ]*open\\(([^()+]*),([^w()]*)\\)", "replacement": "\\1secure_path=\"secure/radix/path/\" \\\\n\\1file_path = os\\.path\\.join\\(secure_path,\\3\\) \\\\n\\1if os.path.commonprefix\\(\\(os.path.realpath\\(file_path\\),secure_path\\)\\) == secure_path:\\\\n\\1    \\2 = open\\(file_path,\\4\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import os" , "comment": "add a check to see if the file exists in a specif path before opening it"}'
    '{"id": 11, "pattern": "([ ]*)([a-zA-Z0-9_]+)[ ]*=[ ]*open\\(([^()]*\\+[^()]*),([^w()]*)\\)", "replacement": "\\1file_path = os\\.path\\.join\\(REPLACE_PATH,REPLACE_VAR\\) \\\\n\\1if os.path.commonprefix\\(\\(os.path.realpath\\(file_path\\),REPLACE_PATH\\)\\) != REPLACE_PATH:\\\\n\\1   \\2 = open\\(file_path,\\4\\)", "source": "\\+([a-zA-Z0-9_ ]+)", "pattern_not": "PLACEHOLDER", "imports": "import os" , "comment": "add a check to see if the file exists in a specif path before opening it"}'
       
    #12 e 13 ridondanti
    '{"id": 12, "pattern": "NO-MATCH-COULD-GENERATE", "replacement": "file_path = os\\.path\\.join\\(\"path\\/\",\\2\\) \\\\n if os\\.path\\.isfile\\(file_path\\): \\\\n \\1=open\\(file_path,\\3\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import os" , "comment": "add a check to see if the file exists in a specif path before opening it"}'
    '{"id": 13, "pattern": "NO-MATCH-COULD-GENERATE", "replacement": "file_path = os\\.path\\.join\\(REPLACE_PATH,REPLACE_VAR\\) \\\\n if os\\.path\\.isfile\\(file_path): \\\\n \\1=open\\(file_path,\\3\\)", "source": "+([a-zA-Z0-9_ ]+)", "pattern_not": "PLACEHOLDER", "imports": "import os" , "comment": "add a check to see if the file exists in a specif path before opening it"}'
    
    '{"id": 14, "pattern": "os\\.mkdir\\(([^()]*)\\+([^()]*)\\)", "replacement": "dir_path = os\\.path\\.join\\(\\1,\\2\\) \\\\n if re\\.match(REG,\\2): \\\\n os\\.mkdir\\(dir_path)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import re" , "comment": "add a check to see if the directory name is valid before creating it"}'
    '{"id": 15, "pattern": "([a-zA-Z0-9_]+)\\.filename", "replacement": "secure_filename\\(\\1\\.filename\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from werkzeug.utils import secure_filename" , "comment": "use the secure_filename function to sanitize the filename before saving it. Consider adding other checks such as file extension and existence of the file"}'
    '{"id": 16, "pattern": "return ([a-zA-Z0-9_]+)\\.text", "replacement": "\\1\\.raise_for_status\\(\\) \\\\n return \\1\\.text", "source": "([a-zA-Z0-9_]+) = requests\\.get", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a check to see if the request was successful before returning the response"}'
    '{"id": 17, "pattern": "([#].*if.*[\\\\n])?([ ]*)if([^:]*)(password|passwd|pass|pwd|pass1)([ ]*)==", "replacement": "\\1\\2password = hashlib\\.sha512\\(\\4\\.encode\\(\\)\\)\\.hexdigest\\(\\) \\\\n\\2if\\3\\4\\5==", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import hashlib" , "comment": "hash the password before comparing it to the stored hash. If you are using a salt, ensure it is unique and random for each user"}'
    
    # non è una remediation corretta
    #'{"id": 18, "pattern": "if([^:]*)(email|e_mail|Email|Mail)", "replacement": "if \\1\\2 and \"\\@\" in \\2", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a check to see if the email address is valid before using it"}'
    '{"id": 18, "pattern": "NO-MATCH-COULD-GENERATE", "replacement": "if \\1\\2 and \"\\@\" in \\2", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a check to see if the email address is valid before using it"}'
    
    '{"id": 19, "pattern": "return open\\(([^()]*),([^w()]*)\\)\\.read\\(\\)", "replacement": "file_path = os\\.path\\.join\\(REPLACE_PATH,REPLACE_VAR) \\\\n if os\\.path\\.isfile\\(file_path\\): \\\\n return open\\(file_path,\\2\\)\\.read\\(\\) \\\\n else return \"Error\"", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data)", "pattern_not": "PLACEHOLDER", "imports": "import os" , "comment": "add a check to see if the file exists in a specif path before reading it"}'
    '{"id": 20, "pattern": "([a-zA-Z0-9_]*)dn = ([^.]*)\\.format\\(([a-zA-Z0-9_]+)\\)", "replacement": "\\1dn = \\2.format\\(escape_rdn\\(\\3\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "escape the RDN before formatting the string"}'
    '{"id": 21, "pattern": "([a-zA-Z0-9_]*)filter = ([^.]*)\\.format\\(([a-zA-Z0-9_]+)\\)", "replacement": "\\1filter = \\2.format\\(escape_filter_chars\\(\\3\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "escape the filter characters before formatting the string"}'
    
    # aggiunta a 22 e 23 di NO-MATCH-COULD-GENERATE per non generare match: va introdotta un'opportuna regola di dection e va adattata la remediation
    '{"id": 22, "pattern": "([a-zA-Z0-9_.]*)logger\\.([a-zA-Z0-9_]*)NO-MATCH-COULD-GENERATE", "replacement": "if not REPLACE_VAR or SPECIAL1 in REPLACE_VAR or SPECIAL2 in REPLACE_VAR or SPECIAL3 in REPLACE_VAR: \\\\n abort\\(404\\) \\\\n else: \\\\n REPLACE_VAR = escape\\(REPLACE_VAR\\) \\\\n \\1logger.\\2", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data|get_json)", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a check to see if the logger variable is valid before using it"}'
    '{"id": 23, "pattern": "([a-zA-Z0-9_.]*)logging\\.([^)]*)NO-MATCH-COULD-GENERATE", "replacement": "if not REPLACE_VAR or SPECIAL1 in REPLACE_VAR or SPECIAL2 in REPLACE_VAR or SPECIAL3 in REPLACE_VAR: \\\\n abort\\(404\\) \\\\n else: \\\\n REPLACE_VAR = escape\\(REPLACE_VAR\\) \\\\n \\1logging.\\2", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data|get_json)", "pattern_not": "if re.match", "imports": "" , "comment": "add a check to see if the logging variable is valid before using it"}'
    
    #patterns with detection rule associated  
    '{"id": 24, "pattern": "yaml\\.load\\(", "replacement": "yaml\\.safe_load\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use safe_load instead of load to avoid code execution"}'
    '{"id": 25, "pattern": "pickle\\.loads\\(", "replacement": "json\\.loads\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import json" , "comment": "use json.loads instead of pickle.loads to avoid code execution"}'
    '{"id": 26, "pattern": "pickle\\.load\\(", "replacement": "json\\.load\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import json" , "comment": "use json.load instead of pickle.load to avoid code execution"}'
    '{"id": 27, "pattern": "pickle\\.dumps\\(", "replacement": "json\\.dumps\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import json" , "comment": "use json.dumps instead of pickle.dumps to avoid code execution"}'
    '{"id": 28, "pattern": "eval\\(", "replacement": "ast\\.literal_eval\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import ast" , "comment": "use ast.literal_eval instead of eval to avoid code execution"}'
    '{"id": 29, "pattern": "debug=True", "replacement": "debug=False, use_debugger=False, use_reloader=False", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "disable the debugger and reloader in production"}'
    '{"id": 30, "pattern": "return traceback\\.format_exc\\(\\)", "replacement": "trace_var = traceback\\.format_exc\\(\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "store the traceback in a variable and consider of not returning it"}'
    '{"id": 31, "pattern": " FTP\\(", "replacement": " FTP_TLS\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import FTP_TLS" , "comment": "use FTP_TLS instead of FTP to secure the connection"}'
    '{"id": 32, "pattern": "import FTP", "replacement": "import FTP_TLS", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use FTP_TLS instead of FTP to secure the connection"}'
    '{"id": 33, "pattern": "ftplib\\.FTP\\(", "replacement": "ftplib\\.FTP_TLS\\(", "source": "", "pattern_not": "PLACEHOLDER","imports": "" , "comment": "use FTP_TLS instead of FTP to secure the connection"}'
    '{"id": 34, "pattern": "smtplib\\.SMTP\\(", "replacement": "smtplib\\.SMTP_SSL\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use SMTP_SSL instead of SMTP to secure the connection"}'
    '{"id": 35, "pattern": "hashlib\\.sha256\\(", "replacement": "hashlib\\.sha512\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use sha512 instead of sha256 for hashing"}'
    '{"id": 36, "pattern": "sha256", "replacement": "sha512", "source": "", "pattern_not": "([a-zA-Z0-9\\s])sha256", "imports": "" , "comment": "use sha512 instead of sha256 for hashing"}'
    '{"id": 37, "pattern": "DSA\\.generate\\([0-9]+\\)", "replacement": "ECC\\.generate(curve=\"P-256\")", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from Crypto.PublicKey import ECC" , "comment": "DSA is a legacy algorithm and should generally be avoided in favor of choices likeEdDSA using curve25519 orECDSA."}'
    '{"id": 38, "pattern": "DES\\.new\\(", "replacement": "AES\\.new\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use AES instead of DES for encryption"}'

    #old
    #'{"id": 39, "pattern": "ssl\\.wrap_socket\\(", "replacement": "SSLContext\\.wrap_socket\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use SSLContext.wrap_socket instead of ssl.wrap_socket for secure connections"}'
    '{"id": 39, "pattern": "([ ]*)([a-zA-Z0-9_]+)[ ]*=[ ]*ssl\\.wrap_socket\\(([a-zA-Z0-9_]+)[ ]*,[^)]*\\)", "replacement": "\\1context = ssl.create_default_context()\\\\n\\1\\2 = context\\.wrap_socket\\(\\3, server_hostname=host\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use SSLContext instead of ssl.wrap_socket for secure connections"}'
    
    '{"id": 40, "pattern": "hashlib\\.md5\\(", "replacement": "hashlib\\.sha512\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import hashlib.sha512" , "comment": "use sha512 instead of md5 for hashing"}'
    '{"id": 41, "pattern": "md5", "replacement": "sha512", "source": "", "pattern_not": "([a-zA-Z0-9\\s])md5", "imports": "import hashlib.sha512" , "comment": "use sha512 instead of md5 for hashing"}'
    '{"id": 42, "pattern": "hashlib\\.sha1\\(", "replacement": "hashlib\\.sha512\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import hashlib.sha512" , "comment": "use sha512 instead of sha1 for hashing"}'
    '{"id": 43, "pattern": "sha1", "replacement": "sha512", "source": "", "pattern_not": "([a-zA-Z0-9\\s])sha1", "imports": "import hashlib.sha512" , "comment": "use sha512 instead of sha1 for hashing"}'
    '{"id": 44, "pattern": "modes\\.CBC\\(", "replacement": "modes\\.GCM\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use GCM instead of CBC for encryption. If you use IV ensure it is random and unique"}'
    '{"id": 45, "pattern": "modes\\.ECB\\(", "replacement": "modes\\.GCM\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use GCM instead of ECB for encryption. If you use IV ensure it is random and unique"}'
    '{"id": 46, "pattern": "AES\\.MODE_CBC", "replacement": "AES\\.MODE_GCM", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use GCM instead of CBC for encryption. If you use IV ensure it is random and unique"}'
    '{"id": 47, "pattern": "AES\\.MODE_ECB", "replacement": "AES\\.MODE_GCM", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use GCM instead of ECB for encryption. If you use IV ensure it is random and unique"}'
    '{"id": 48, "pattern": "random\\.randint\\(", "replacement": "secrets\\.SystemRandom\\(\\)\\.randrange\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import secrets" , "comment": "use secrets.SystemRandom instead of random for generating random numbers"}'
    '{"id": 49, "pattern": "import random", "replacement": "import secrets", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use secrets instead of random for generating random numbers"}'
    '{"id": 50, "pattern": "random\\.choice\\(", "replacement": "secrets\\.choice\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import secrets" , "comment": "use secrets.choice instead of random.choice for generating random numbers"}'
    '{"id": 51, "pattern": "random\\.choices\\(([^,]+),([ ]*k[ ]*=[ ]*)([a-zA-Z0-9_]+)\\)", "replacement": "secrets\\.choice\\(\\1\\) for _ in range\\(\\3\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import secrets" , "comment": "use secrets.choice instead of random.choices for generating random numbers"}'
    '{"id": 52, "pattern": "random\\.getrandbits\\(", "replacement": "secrets\\.randbits\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import secrets" , "comment": "use secrets.randbits instead of random.getrandbits for generating random numbers"}'
    '{"id": 53, "pattern": "jwt\\.process_jwt\\(([^)]*)\\)", "replacement": "jwt\\.process_jwt\\(\\1, \"key\", algorithms=[\"HS512\"]\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "Use a key and algorithm for decoding the JWT. The secret key should not be wired into the code"}'
    #'{"id": 54, "pattern": "(mktemp|mkstemp)\\(", "replacement": "TemporaryFile\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use TemporaryFile instead of mktemp or mkstemp for creating temporary files"}'
    '{"id": 54, "pattern": "NO-REMEDIATION-PATTERN", "replacement": "TemporaryFile\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use TemporaryFile instead of mktemp or mkstemp for creating temporary files"}'

    '{"id": 55, "pattern": "clock\\(", "replacement": "perf_counter\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use perf_counter instead of clock for measuring time"}'
    '{"id": 56, "pattern": "\\b(pickle|cPickle)\\.\\b", "replacement": "json\\.", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use json instead of pickle for serialization"}'
    '{"id": 57, "pattern": "import (pickle|cPickle|_pickle) as (pickle|cPickle)", "replacement": "import json", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use json instead of pickle for serialization"}'
    '{"id": 58, "pattern": "import (pickle|cPickle|_pickle)", "replacement": "import json", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use json instead of pickle for serialization"}'
    '{"id": 59, "pattern": "\\.pkl", "replacement": "\\.json", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import json" , "comment": "use json instead of pickle for serialization"}'
    #old
    #'{"id": 60, "pattern": "xml\\.sax\\.", "replacement": "defusedxml\\.sax\\.", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import defusedxml" , "comment": "use defusedxml instead of xml.sax for parsing XML"}'
    '{"id": 60, "pattern": "([ ]*)([a-zA-Z0-9_]+)[ ]*=[ ]*xml\\.sax\\.make_parser\\(\\)", "replacement": "\\1\\2 = xml\\.sax\\.make_parser\\(\\)\\\\n\\1\\2\\.setFeature\\(xml\\.sax\\.handler\\.feature_external_ges, False\\)\\\\n\\1\\2\\.setFeature\\(xml\\.sax\\.handler\\.feature_external_pes, False\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import xml.sax" , "comment": "use setFeature to disable external entities in the XML parser or consider using defusedxml instead of xml.sax for parsing XML"}'
    '{"id": 61, "pattern": "(xml\\.)?etree\\.ElementTree", "replacement": "defusedxml\\.ElementTree", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import defusedxml" , "comment": "use defusedxml instead of xml.etree.ElementTree for parsing XML"}'
    '{"id": 62, "pattern": "import xml", "replacement": "import defusedxml", "source": "", "pattern_not": "import xml\\.", "imports": "" , "comment": "use defusedxml instead of xml for parsing XML"}'
    '{"id": 63, "pattern": "assert(.*)", "replacement": "try:\\\\n    assert \\1\\\\n except AssertionError as msg: \\\\n    print\\(msg\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use try-except block to catch the AssertionError"}'
    '{"id": 64, "pattern": "hashlib\\.new\\(([^)]*)\\)", "replacement": "hashlib\\.new\\(\"sha512\", usedforsecurity=True\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use sha512 instead of md5 or sha1 for hashing"}'
    '{"id": 65, "pattern": "pbkdf2_hmac\\(([^),]*),([^),]*)\\)", "replacement": "pbkdf2_hmac\\(\"sha512\",\\2\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use sha512 instead of md5 or sha1 for hashing"}'
    #old
    #'{"id": 66, "pattern": "parseUDPpacket\\(", "replacement": "parseTCPpacket\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use parseTCPpacket instead of parseUDPpacket for parsing packets"}'
    '{"id": 66, "pattern": "NO-REMEDIATION-PATTERN", "replacement": "parseTCPpacket\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "Consider using TCP instead of UDP"}'
    
    '{"id": 67, "pattern": "os\\.system\\(([^a-z]*)([a-z]*)\\.bin", "replacement": "os\\.system\\(\\1\\2\\.txt", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use txt instead of bin for system commands"}'
    '{"id": 68, "pattern": "requests\\.(.*)\\((.*)verify([ ]*)=([ ]*)False", "replacement": "requests\\.\\1\\(\\2verify\\3=\\4True", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use verify=True instead of verify=False for secure connections"}'
    '{"id": 69, "pattern": "set_cookie\\(([^,]+,[ a-zA-Z0-9_]+)(,)?", "replacement": "set_cookie\\(\\1, max_age=3600\\2", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use a date for the cookie expiration"}'
    '{"id": 70, "pattern": "check_hostname([ ]*)=([ ]*)False", "replacement": "check_hostname=True", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use check_hostname=True for secure connections"}'
    '{"id": 71, "pattern": "verify_mode([ ]*)=([ ]*)([a-zA-Z_.]+)", "replacement": "verify_mode=ssl\\.CERT_REQUIRED", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use ssl.CERT_REQUIRED for secure connections"}'
    '{"id": 72, "pattern": "create_unverified_context\\(\\)", "replacement": "create_default_context\\(\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use create_default_context instead of create_unverified_context for secure connections"}'
    '{"id": 73, "pattern": "_create_unverified_context = True", "replacement": "check_hostname = True", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use check_hostname=True for secure connections"}'
    '{"id": 74, "pattern": "ssl\\._create_stdlib_context\\(\\)", "replacement": "ssl\\.create_default_context\\(\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use ssl.create_default_context instead of ssl._create_stdlib_context for secure connections"}'
    '{"id": 75, "pattern": "(ssl|SSL)\\.(SSLv2|SSLv3|SSLv23|TLSv1|TLSv1_1)_METHOD", "replacement": "SSL\\.TLS_METHOD", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use secure versions like TLS 1.2 or TLS 1.3"}'
    '{"id": 76, "pattern": "\\.PROTOCOL_(SSLv2|SSLv3|TLSv1(_1)?)", "replacement": "\\.PROTOCOL_TLSv1_2", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use secure versions like TLS 1.2 or TLS 1.3"}'
    '{"id": 77, "pattern": "urandom\\(([^)]*)\\)", "replacement": "urandom\\(64\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use urandom(64) instead of urandom(n) for generating random numbers"}'
    '{"id": 78, "pattern": "key_size=([0-9 ]*)", "replacement": "key_size=2048", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use a key size of 2048 bits for secure connections"}'
    '{"id": 79, "pattern": "jwt\\.decode\\(([^)]*), verify[ ]*=[ ]*False\\)", "replacement": "jwt\\.decode\\(\\1, \"secret-key\", algorithms=\\[\"HS512\"\\]\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "Use a key and algorithm for decoding the JWT. The secret key should not be wired into the code"}'
    '{"id": 80, "pattern": "jwt\\.decode\\(([^)]*)options=([^)]*)False([^)]*)\\)", "replacement": "jwt\\.decode\\(\\1 algorithms=\\[\"HS512\"\\]\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "Use a key and algorithm for decoding the JWT. The secret key should not be wired into the code"}'
    #'{"id": 81, "pattern": "\\.bind\\(\\((.0\\.0\\.0\\.0.|.{2})", "replacement": "\\.bind\\(\\(\"127\\.0\\.0\\.0\\"", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "avoid binding to all interfaces"}'
    '{"id": 81, "pattern": "\\.bind\\(\\((.0\\.0\\.0\\.0.|.{2})", "replacement": "\\.bind\\(\\(\"127\\.0\\.0\\.1\"", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "avoid binding to all interfaces"}'
    
    #'{"id": 82, "pattern": "XMLParser\\(([^)]*)\\)", "replacement": "DefusedXMLParser\\(\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import defusedxml.ElementTree" , "comment": "use DefusedXMLParser instead of XMLParser for parsing XML"}'
    '{"id": 82, "pattern": "NO-MATCH-COULD-GENERATE", "replacement": "DefusedXMLParser\\(\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import defusedxml.ElementTree" , "comment": "use DefusedXMLParser instead of XMLParser for parsing XML"}'

    
    '{"id": 83, "pattern": "XSLTAccessControl\\(([^)]*)\\)", "replacement": "XSLTAccessControl\\.DENY_ALL", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use XSLTAccessControl.DENY_ALL instead of XSLTAccessControl for secure connections"}'
    
    #old
    #'{"id": 84, "pattern": "([a-zA-Z0-9._]+) = Lock\\(\\)(.*)\\1\\.acquire\\(\\)", "replacement": "\\1 = Lock() \\\\n if \\1.locked(): \\\\n     \\1.acquire()", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a check to see if the lock is already acquired before acquiring it"}'
    '{"id": 84, "pattern": "NO-REMEDIATION-PATTERN", "replacement": "NO-REPLACEMENT-PATTERN", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "add a check to see if the lock is already acquired before acquiring it"}'
    
    '{"id": 85, "pattern": "import csv", "replacement": "import defusedcsv", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use defusedcsv instead of csv for parsing CSV"}'
    '{"id": 86, "pattern": "csv\\.", "replacement": "defusedcsv\\.", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "import defusedcsv" , "comment": "use defusedcsv instead of csv for parsing CSV"}'
    '{"id": 87, "pattern": "Markup\\(", "replacement": "Markup\\.escape\\(", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use Markup.escape instead of Markup for escaping HTML"}'
    '{"id": 88, "pattern": "Markup\\.unescape\\(", "replacement": "Markup\\.escape\\(", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use Markup.escape instead of Markup.unescape for escaping HTML"}'
    '{"id": 89, "pattern": "subprocess\\.capture_output\\(([^)]*)\\)", "replacement": "subprocess\\.run\\(\\1, capture_output=True, check=True, text=True\\)", "source": "PLACEHOLDER", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use subprocess.run instead of subprocess.capture_output for capturing the output"}'
    '{"id": 90, "pattern": "Environment\\((.*)autoescape[ ]*=[ ]*False", "replacement": "Environment\\(\\1autoescape=True", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use autoescape=True instead of autoescape=False for escaping HTML"}'
    '{"id": 91, "pattern": "Environment\\(([^\\\\n]*)\\)", "replacement": "Environment(\\1, autoescape=True\\)", "source": "", "pattern_not": "autoescape", "imports": "" , "comment": "use autoescape=True for escaping HTML"}'
    '{"id": 92, "pattern": "shell([ ]*)=([ ]*)True", "replacement": "shell=False", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use shell=False instead of shell=True for secure connections"}'
    
    #ci vorrebbe una regola di detection per identificare la srogente iniettata in os.system
    #'{"id": 93, "pattern": "os\\.system\\((.*)\\)\\\\n{1}", "replacement": "subprocess\\.run\\(REPLACE_HERE_LIST, check=True\\)", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data|headers|params)\\get\\(", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use subprocess.run instead of os.system for executing commands"}'
    '{"id": 93, "pattern": "NO-REMEDIATION-PATTERN", "replacement": "NO-REPLACEMENT-PATTERN", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data|headers|params)\\get\\(", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use subprocess.run for executing commands"}'
    
    '{"id": 94, "pattern": "([a-zA-Z0-9_.]+)\\.execute\\((.*(WHERE|where|VALUES|values).*)\\)", "replacement": "query_variable=REPLACE_QUERY \\\\n \\1\\.execute\\(query_variable,\\(REPLACE_VAR,\\)\\)", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data|get|params)", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use query variables instead of string concatenation for executing queries"}'
    '{"id": 95, "pattern": "(order_by|filter|like|group_by|like|distinct|extra)\\(([^)]*)\\(([^)]*)\\)\\)", "replacement": "\\1\\(param=\\3\\)\\.first\\(\\)", "source": "", "pattern_not": "PLACEHOLDER"}'
    '{"id": 96, "pattern": "([ ]*)with open\\(([^,+]*),([^w()]*)\\)[ ]*as[ ]*([a-zA-Z0-9_]+)[ ]*:[ ]*\\\\n", "replacement": "\\1secure_path=\"secure/radix/path/\" \\\\n\\1file_path = os\\.path\\.join\\(secure_path,\\2\\) \\\\n\\1if os.path.commonprefix\\(\\(os.path.realpath\\(file_path\\),secure_path\\)\\) == secure_path: \\\\n\\1    with open\\(file_path,\\3\\) as \\4:\\\\n    ", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data)", "pattern_not": "return open", "imports": "import os" , "comment": "add a check to see if the file exists in a specific path before opening it"}'
    '{"id": 97, "pattern": "([ ]*)with open\\(([^()]*\\+[^()]*),([^w()]*)\\)", "replacement": "\\1file_path = os\\.path\\.join\\(REPLACE_PATH,REPLACE_VAR\\) \\\\n\\1if os.path.commonprefix\\(\\(os.path.realpath\\(file_path\\),REPLACE_PATH\\)\\) != REPLACE_PATH: \\\\n\\1    with open\\(file_path,\\3\\)", "source": "([a-zA-Z0-9_]+) = (flask\\.)?request\\.(args|GET|POST|files|form|data)", "pattern_not": "(return|with) open", "imports": "import os" , "comment": "add a check to see if the file exists in a specific path before opening it"}'
    # old remdiation built-in detecrion rules: permissions 0o400 are ok
    #'{"id": 98, "pattern": "os\\.chmod\\(([^()]*), ([o0-9]+)\\)", "replacement": "os\\.chmod\\(\\1, 0o600\\)", "source": "", "pattern_not": "os\\.chmod\\([^,]*,[ ]*0o400[ ]*\\)"}'
    '{"id": 98, "pattern": "os\\.chmod\\(([^()]*), ([o0-9]+)\\)", "replacement": "os\\.chmod\\(\\1, 0o600\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use 0o600 instead others for file permissions"}'
   
    # old remdiation built-in detecrion rules
    '{"id": 99, "pattern": "(.*)\\(([^+]*)\\+[ ]*request\\.args\\.get\\(([^)]*)\\)", "replacement": "f=request\\.args\\.get\\(\\3\\) \\\\n f_p = os\\.path\\.join\\(\"img\", escape\\(f\\)\\) \\\\n if os\\.path\\.realpath\\(f_p\\)\\.startswith\\(os\\.path\\.realpath\\(\\2\\)\\):\\\\n \\1\\(\\2+f_p", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "add a check to see if the file exists in a specific path before opening it"}'
    '{"id": 100, "pattern": "(.*)\\(([^+]*)\\+[ ]*request\\.args\\[([^]]*)\\]", "replacement": "f=request\\.args\\[\\3\\] \\\\n f_p = os\\.path\\.join\\(\"img\", escape\\(f\\)\\) \\\\n if os\\.path\\.realpath\\(f_p\\)\\.startswith\\(os\\.path\\.realpath\\(\\2\\)\\):\\\\n \\1\\(\\2+f_p", "source": "", "pattern_not": "PLACEHOLDER", "imports": "import os" , "comment": "add a check to see if the file exists in a specific path before opening it"}'
    '{"id": 101, "pattern": "request\\.POST\\.get\\(([^)]*)\\)", "replacement": "escape\\(request\\.POST\\.get\\(\\1\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the POST parameter before using it"}'
    '{"id": 102, "pattern": "(\\+|=)[ ]*\\bINJECTED_VAR\\b", "replacement": "\\1 escape\\(INJECTED_VAR\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 103, "pattern": "\\bINJECTED_VAR\\b[ ]*:", "replacement": "escape\\(INJECTED_VAR\\):", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 104, "pattern": "\\([ ]*\\bINJECTED_VAR\\b[ ]*", "replacement": "\\(escape\\(INJECTED_VAR\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 105, "pattern": "[ ]*\\bINJECTED_VAR\\b[ ]*\\)", "replacement": "escape\\(INJECTED_VAR\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 106, "pattern": "%[ ]*\\bINJECTED_VAR\\b[ ]*", "replacement": "%escape\\(INJECTED_VAR\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 107, "pattern": "return [ ]*\\bINJECTED_VAR\\b", "replacement": "return escape\\(INJECTED_VAR\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before returning it"}'
    '{"id": 108, "pattern": "requests\\.get\\(\\bINJECTED_VAR\\b", "replacement": "escape\\requests\\.get\\((INJECTED_VAR\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents  before using it"}'
    '{"id": 109, "pattern": "return requests\\.get\\(([^)]*)\\)", "replacement": "return escape\\(request\\.get\\(\\1\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before returning it"}'
    '{"id": 110, "pattern": "int\\([ ]*\\bINJECTED_VAR\\b", "replacement": "int\\(escape\\(INJECTED_VAR\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 111, "pattern": "\\[[ ]*\\bINJECTED_VAR\\b[ ]*", "replacement": "\\[escape\\(INJECTED_VAR\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 112, "pattern": "[ ]*\\bINJECTED_VAR\\b[ ]*\\]", "replacement": "escape\\(INJECTED_VAR\\)\\]", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 113, "pattern": "[ ]*\\bINJECTED_VAR\\b\\.", "replacement": "escape\\(INJECTED_VAR\\)\\.", "source": "", "pattern_not": "PLACEHOLDER"}, "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 114, "pattern": "request\\.args\\.get\\[([^]]*)\\]", "replacement": "escape\\(request\\.args\\.get\\[\\1\\]\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 115, "pattern": "urlparse\\(([^)]*)\\)", "replacement": "escape\\(urlparse\\(\\1\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 116, "pattern": "return urlparse\\(([\\)])\\)", "replacement": "return escape\\(urlparse\\(\\1\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before returning it"}'
    '{"id": 117, "pattern": "\\{[ ]*\\bINJECTED_VAR\\b[ ]*\\}", "replacement": "\\{escape\\(INJECTED_VAR\\)\\}", "source": "", "pattern_not": "\\{\\{[ ]*INJECTED_VAR[ ]*\\}", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 118, "pattern": "return (flask\\.)?request\\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\.get\\(([^)]*)\\)", "replacement": "return escape\\(\\1request\\.\\2\\.get\\(\\3\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 119, "pattern": "return (flask\\.)?request\\.(args|args\\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\[([^]]*)\\]", "replacement": "return escape\\(\\1request\\.\\2\\[\\3\\]\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 120, "pattern": "return (flask\\.)?request\\.(get|urlopen|read|get_data|get_json|from_values)\\(([^)]*)\\)", "replacement": "return escape\\(\\1request\\.\\2\\(\\3\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 121, "pattern": "\\+[ ]*(flask\\.)?request\\.(args|args\\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\[([^]]*)\\]", "replacement": "\\+ escape\\(\\1request\\.\\2\\[\\3\\]\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 122, "pattern": "\\+[ ]*(flask\\.)?request\\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\.get\\(([^)]*)\\)", "replacement": "\\+ escape\\(\\1request\\.\\2\\.get\\(\\3\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 123, "pattern": "\\([ ]*(flask\\.)request\\.(args|args\\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\(([^)]*)\\)", "replacement": "\\(escape\\(\\1request\\.\\2\\(\\3\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 124, "pattern": "\\%[ ]*(flask\\.)request\\.(args|args\\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\(([^)]*)\\)", "replacement": "\\% escape\\(\\1request\\.\\2\\(\\3\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    #'{"id": 125, "pattern": "\\((.*)=[ ]*input\\(\\)", "replacement": "\\(\\1= escape\\(input\\(\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from flask import escape" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 125, "pattern": "NO-REMEDIATION-PATTERN", "replacement": "NO-REPLACEMENT-PATTERN", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "validate contets of variabile acquired with input function before using it"}'

    '{"id": 126, "pattern": "[a-zA-Z0-9_]+[ ]*=[ ]*(etree\\.)?XSLTAccessControl\\(.*(read_network|write_network)[^)]*\\)", "replacement": "parser = \\1XSLTAccessControl\\(resolve_entities=False\\) \\\\n  REPLACE_VAR = etree\\.XSLTAccessControl\\.DENY_ALL \\\\n", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use XSLTAccessControl.DENY_ALL instead of XSLTAccessControl for secure connections"}'
    '{"id": 127, "pattern": "while ([^<]*)<([^:]*)", "replacement": "while  \\1< \\2\\\\n \\1\\+\\+", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "remember to increment the variable in the loop"}'
    '{"id": 128, "pattern": "jwt\\.decode\\(([a-zA-Z0-9_]*)\\)", "replacement": "jwt\\.decode\\(\\1, \"secret-key\", algorithms=[\"HS512\"]\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use a key and algorithm for decoding the JWT. The secret chaive should not be wired into the code"}'
    '{"id": 129, "pattern": "(def[^(]*\\(.*)(escape\\(\\bINJECTED_VAR\\b\\))([^:)]*(,escape\\(.*\\))?\\):)", "replacement": "\\1 INJECTED_VAR \\3", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "escape the variable and validate contents before using it"}'
    '{"id": 130, "pattern": "NO-REMEDIATION-PATTERN", "replacement": "NO-REPLACEMENT-PATTERN", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "you should not use exec()-like function"}'
    '{"id": 131, "pattern": "set_cookie\\(([^,]+,[ a-zA-Z0-9_]+)(,)?", "replacement": "set_cookie\\(\\1, httponly=True\\2", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "set the HttpOnly flag for the cookie"}'
    '{"id": 132, "pattern": "set_cookie\\(([^,]+,[ a-zA-Z0-9_]+)(,)?", "replacement": "set_cookie\\(\\1, secure=True\\2", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "set the Secure flag for the cookie"}'
    '{"id": 133, "pattern": "set_cookie\\(([^,]+,[ a-zA-Z0-9_]+)(,)?", "replacement": "set_cookie\\(\\1, samesite=True\\2", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "set the Samesite flag for the cookie"}'
    '{"id": 134, "pattern": "from Crypto\\.PublicKey import DSA", "replacement": "from Crypto\\.PublicKey import ECC", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "DSA is a legacy algorithm and should generally be avoided in favor of choices likeEdDSA using curve25519 orECDSA."}'
    '{"id": 135, "pattern": "DSA\\.import_key\\(", "replacement": "ECC\\.import_key\\(", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from Crypto.PublicKey import ECC" , "comment": "DSA is a legacy algorithm and should generally be avoided in favor of choices likeEdDSA using curve25519 orECDSA."}'
    '{"id": 136, "pattern": "NO-REMEDIATION-PATTERN", "replacement": "NO-REPLACEMENT-PATTERN", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "DSA is a legacy algorithm and should generally be avoided in favor of choices likeEdDSA using curve25519 orECDSA. Consider using ECC.construct instead."}'
    '{"id": 137, "pattern": "dsa\\.generate_private_key\\([^)]+\\)", "replacement": "ec\\.generate_private_key\\(ec.SECP384R1\\(\\)\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "from cryptography.hazmat.primitives.asymmetric import ec" , "comment": "DSA is a legacy algorithm and should generally be avoided in favor of choices likeEdDSA using curve25519 or ECDSA."}'
    '{"id": 138, "pattern": "from cryptography.hazmat.primitives.asymmetric import dsa", "replacement": "from cryptography.hazmat.primitives.asymmetric import ec", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "DSA is a legacy algorithm and should generally be avoided in favor of choices likeEdDSA using curve25519 orECDSA."}'
    '{"id": 139, "pattern": "NO-REMEDIATION-PATTERN", "replacement": "NO-REPLACEMENT-PATTERN", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "DSA is a legacy algorithm and should generally be avoided in favor of choices likeEdDSA using curve25519 orECDSA."}'

    '{"id": 140, "pattern": "etree\\.XMLParser\\([^)]*\\)", "replacement": "etree\\.XMLParser\\(dtd_validation=True, resolve_entities=False, no_network=True\\)", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use XMLParser with dtd_validation=True, resolve_entities=False, no_network=True for parsing XML"}'
    '{"id": 141, "pattern": "NO-REMEDIATION-PATTERN", "replacement": "NO-REPLACEMENT-PATTERN", "source": "", "pattern_not": "PLACEHOLDER", "imports": "" , "comment": "use XMLParser of defusedxml.ElementTree library for parsing XML"}'

)

# Dichiarazione dell'array dei patterns
declare -a patterns
declare -a replacements
declare -a sources
declare -a patterns_not
declare -a injected_vars=()
declare -a comments
declare -a imports
declare -a selectedImports
declare -a selectedComments

######################################### NEW REMEDIATION CODE
# questo è un vettore che contiene gli ID delle remdiation da eseguire
declare -a remdiationToExecute=()
# Funzione per aggiungere una remediation all'array delle remediation se non è già presente
add_remediation() {
    local new_rem=$1 #indice della remediation da aggiungere
    local new_injected_var=${2:-} #eventuale variabile da iniettare (è opzionale)
    
    # Se è stata fornita una variabile da iniettare, aggiungila all'array injected_vars
    if [ -n "$new_injected_var" ]; then
        #injected_vars[$new_rem]="$new_injected_var"
        #injected_vars+=($new_injected_var)
        echo "Variabile $new_injected_var iniettata nella"
    else 
        #se non è presente una vairiabile da iniettare controlliamo se la regola è già presente
        new_injected_var="INVALID_INJECTED_VAR"

        for rem in "${remdiationToExecute[@]}"; do 
            if [ "$rem" -eq "$new_rem" ]; then
                return
            fi
        done
    fi
    #echo "Variabile $new_injected_var iniettata nella remediation $new_rem"
    injected_vars+=($new_injected_var)
    remdiationToExecute+=($new_rem)

    echo "Remediation $new_rem aggiunta all'array."
    
}

# Aggiungi gli indici da 0 a 23 (remediation a cui non è associata algune regola di detection all'array usando la funzione add_remediation
for (( i=0; i<=23; i++ )); do
    add_remediation $i
    #injected_vars+=("")
done



######################################### END NEW REMEDIATION CODE

# Itera attraverso le configurazioni dei pattern
for config in "${pattern_configs[@]}"; do
    # Estrai i valori pattern dalla configurazione JSON
    pattern=$(echo "$config" | jq -r '.pattern')
    replacement=$(echo "$config" | jq -r '.replacement')
    source=$(echo "$config" | jq -r '.source')
    pattern_not=$(echo "$config" | jq -r '.pattern_not')
    import=$(echo "$config" | jq -r '.imports')
    comment=$(echo "$config" | jq -r '.comment') #new

    # Aggiungi il pattern all'array patterns
    patterns+=("$pattern")
    replacements+=("$replacement")
    sources+=("$source")
    patterns_not+=("$pattern_not")
    imports+=("$import")
    comments+=("$comment") #new
    
done
######################################### NEW REMEDIATION

countvuln=0; 
dimtestset=0;
contNoMod=0;
contMod=0;

name_os=$(uname) #OS-system

# VARIABLES FOR OWASP MAPPING - GLOBAL COUNTERS
inj_count=0;  # Injection
crypto_count=0; # Cryptografic Failures
sec_mis_count=0; # Security Misconfiguration
bac_count=0;  # Broken Access Control
id_auth_count=0; # Identification and Authentication Failures
sec_log_count=0; # Secuirty Logging and Monitoring Failures 
ins_des_count=0; # Insecure Design
ssrf_count=0; # SSRF
soft_data_count=0; # Software and Data Integrity Failures


while IFS= read -r line; do

    #initial timestamp all rules for snippet
    start_snippet=$(date +%s.%N)
    if [ ! -z "$line" ]; then
        num_occ=0;
        pass=0;
        modify=0;
        rem_line=$line;
        cng_line=$rem_line;
        var=
        vuln=


        # VARIABLES FOR OWASP MAPPING  
        inj=0;  # Injection
        crypto=0; # Cryptografic Failures
        sec_mis=0; # Security Misconfiguration
        bac=0;  # Broken Access Control
        id_auth=0; # Identification and Authentication Failures
        sec_log=0; # Secuirty Logging and Monitoring Failures 
        ins_des=0; # Insecure Design
        ssrf=0; # SSRF
        soft_data=0; # Software and Data Integrity Failures


        #RULE 1: if exists a the following pattern: = (..+request.args.get())
        echo $line | grep -E -q "\+request.args.get\(|\+ request.args.get\("
        if [ $? -eq 0 ]; then 
            #parameters=$(echo $line | awk -F 'request.args.get\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
            #path=$(echo $line | awk -F 'request.args.get\\(' '{print $1}' | awk -F  '+' '{print $1}' | awk -F  '\\(' '{print $2}')

            #rem_line=$(echo $rem_line | sed "s/+request.args.get($parameters)/+f_p/g" | sed "s/+request.args.get($parameters )/+f_p/g" | sed "s/+ request.args.get($parameters)/+ f_p/g" | sed "s/+ request.args.get($parameters )/+ f_p/g" )
            #rem_line="f=request.args.get($parameters) \\n f_p = os.path.join('img/', escape(f)) \\n if os.path.realpath(f_p).startswith(os.path.realpath($path)): \\n $rem_line"
            #cng_line=$(echo $cng_line | sed "s/+request.args.get($parameters)/+F_P/g" | sed "s/+request.args.get($parameters )/+F_P/g" | sed "s/+ request.args.get($parameters)/+ F_P/g" | sed "s/+ request.args.get($parameters )/+ F_P/g" )
            #cng_line="F=REQUEST.ARGS.GET($parameters) \\n F_P = OS.PATH.JOIN('img/', ESCAPE(F)) \\n IF OS.PATH.REALPATH(F_P).STARTSWITH(OS.PATH.REALPATH($path)): \\n $cng_line"
            add_remediation 99
            modify=1;
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi
        # echo "rule 1"

        #RULE 2: if exists a the following pattern: = (..+request.args[])
        echo $line | grep -q "(.*+request.args\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
            if [ $? -eq 0 ]; then
                #parameters=$(echo $line | awk -F 'request.args\\[' '{print $2}' | awk -F  '\\]' '{print $1}')
                #path=$(echo $line | awk -F 'request.args\\[' '{print $1}' | awk -F  '+' '{print $1}' | awk -F  '\\(' '{print $2}')
                #rem_line=$(echo $rem_line | sed "s/+request.args\[$parameters\]/+f_p/g" | sed "s/+request.args\[$parameters \]/+f_p/g" | sed "s/+ request.args\[$parameter\]/+ f_p/g" | sed "s/+ request.args\[$parameters \]/+ f_p/g" )
                #rem_line="f=request.args[$parameters] \\n f_p = os.path.join('img/', escape(f)) \\n if os.path.realpath(f_p).startswith(os.path.realpath($path)): \\n $rem_line"
                #cng_line=$(echo $cng_line | sed "s/+request.args\[$parameters\]/+F_P/g" | sed "s/+request.args\[$parameters \]/+F_P/g" | sed "s/+ request.args\[$parameter\]/+ F_P/g" | sed "s/+ request.args\[$parameters \]/+ F_P/g" )
                #cng_line="F=REQUEST.ARGS[$parameters] \\n F_P = OS.PATH.JOIN('img/', ESCAPE(F)) \\n IF OS.PATH.REALPATH(F_P).STARTSWITH(OS.PATH.REALPATH($path)): \\n $cng_line"
                add_remediation 100
                modify=1;
                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi
        # echo "rule 2"

        #RULE 3: if exists a the following pattern: = (request.POST.get())
        echo $line | grep -q "(request.POST.get(.*%"
        if [ $? -eq 0 ]; then
            #parameters=$(echo $line | awk -F 'request.POST.get\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
            #rem_line=$(echo $rem_line | sed "s/request.POST.get($parameters)/escape(request.POST.get($parameters))/g" | sed "s/request.POST.get($parameters )/escape(request.POST.get($parameters))/g" )
            #cng_line=$(echo $cng_line | sed "s/request.POST.get($parameters)/ESCAPE(REQUEST.POST.GET($parameters))/g" | sed "s/request.POST.get($parameters )/ESCAPE(REQUEST.POST.GET($parameters))/g" )
            add_remediation 101
            modify=1;
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi
        # echo "rule 3"
        

        #RULE 4: if exists a the following pattern: = requests.get()
        num_occ=$(echo $line | awk -F "requests.get\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "requests.get\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "requests.get\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/requests.get($var)/requests.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/requests.get($var/requests.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/requests.get(\\\\\"$var\\\\\", $var/requests.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "requests.get\\\(" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi
            
                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        add_remediation 102 $var
                                        add_remediation 129 $var
                                        modify=1;
                                        if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Identification and Authentication Failures"
                                            let id_auth=id_auth+1
                                        fi
                                        if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, SSRF"
                                            let ssrf=ssrf+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var *\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            add_remediation 103 $var
                                            add_remediation 129 $var
                                            modify=1;
                                            if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Identification and Authentication Failures"
                                                let id_auth=id_auth+1
                                            fi
                                            if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, SSRF"
                                                let ssrf=ssrf+1
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    add_remediation 104 $var
                                                    add_remediation 129 $var
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        add_remediation 105 $var
                                                        add_remediation 106 $var
                                                        add_remediation 129 $var
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Identification and Authentication Failures"
                                                    let id_auth=id_auth+1
                                                fi
                                                if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, SSRF"
                                                    let ssrf=ssrf+1
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                                if [ $? -eq 0 ]; then
                                                    #parameters=$(echo $line | awk -F 'return requests.get\\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                                                    #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/requests.get($var/escape(requests.get($var)/g" ) #modificata
                                                    #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/requests.get($var/ESCAPE(REQUESTS.GET($var)/g" )
                                                    add_remediation 107 $var
                                                    add_remediation 129 $var
                                                    modify=1;
                                                    if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                        vuln="$vuln, Identification and Authentication Failures"
                                                        let id_auth=id_auth+1
                                                    fi
                                                    if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                        vuln="$vuln, SSRF"
                                                        let ssrf=ssrf+1
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi

            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 4"
            

        #RULE 5: if exists a the following pattern: return requests.get(...)
        echo $line | grep -q "return requests.get("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #parameters=$(echo $line | awk -F 'return requests.get\\\(' '{print $2}' | awk -F  '\\\)' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/return requests.get($parameters/variable = requests.get($parameters) return escape(variable/g" )
                    #cng_line=$(echo $cng_line | sed "s/return requests.get($parameters/VARIABLE = REQUESTS.GET($parameters) RETURN ESCAPE(VARIABLE/g" )
                    modify=1;
                    if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Identification and Authentication Failures"
                        let id_auth=id_auth+1
                    fi
                    if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, SSRF"
                        let ssrf=ssrf+1
                    fi
                fi
            fi
        fi
        # echo "rule 5"
    


        #RULE 6: var is the name of the variable before = input()
        num_occ=$(echo $line | awk -F "int\\\(input\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "int\\\(input\\\(" -v i="$i" '{print $i}' | awk -F "=" '{print $1}' | awk '{print $NF}')
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "int\\\(input\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
            fi
        
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    # echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                    # if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                        if [ $? -eq 0 ]; then
                            #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                            #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                            #add_remediation 102 $var
                            #add_remediation 129 $var
                            add_remediation 125
                            modify=1;
                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Injection"
                                let inj=inj+1
                            fi
                            if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Security Logging and Monitoring Failures"
                                let sec_log=sec_log+1
                            fi
                        fi
                    # fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        # echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                        # if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                #add_remediation 103 $var
                                #add_remediation 129 $var
                                add_remediation 125
                                modify=1;
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
                                fi
                                if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Security Logging and Monitoring Failures"
                                    let sec_log=sec_log+1
                                fi
                            fi
                        # fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            # echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                            # if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                        #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                        #add_remediation 104 $var
                                        #add_remediation 129 $var
                                        add_remediation 125
                                        modify=1;
                                    else
                                        echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                            #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                            #add_remediation 105 $var
                                            #add_remediation 106 $var
                                            #add_remediation 129 $var
                                            add_remediation 125
                                            modify=1;
                                        fi
                                    fi
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"
                                        let inj=inj+1
                                    fi
                                    if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Security Logging and Monitoring Failures"
                                        let sec_log=sec_log+1
                                    fi
                                fi
                            # fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                # echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                # if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                        #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                        #add_remediation 107 $var
                                        #add_remediation 129 $var
                                        add_remediation 125
                                        modify=1;
                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
                                        fi
                                        if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Security Logging and Monitoring Failures"
                                            let sec_log=sec_log+1
                                        fi
                                    fi
                                # fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 6"

        #RULE 7: var is the name of the variable before = input()
        num_occ=$(echo $line | awk -F " input\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F " input\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F " input\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi     
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F " input\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo "$new_line" |awk -F" input\\\(" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                #new_line=$(echo $new_line | cut -d\) -f$split- )
            fi
            # echo "var = $var"
            # echo "new line = $new_line"
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    # echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                    # if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                        if [ $? -eq 0 ]; then
                            #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                            #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                            #add_remediation 102 $var
                            #add_remediation 129 $var
                            add_remediation 125
                            modify=1;
                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Injection"
                                let inj=inj+1
                            fi
                            if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Security Logging and Monitoring Failures"
                                let sec_log=sec_log+1
                            fi
                        fi
                    # fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        # echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                        # if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                            if [ $? -eq 0 ]; then
                                #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                #add_remediation 103 $var
                                #add_remediation 129 $var
                                add_remediation 125
                                modify=1;
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
                                fi
                                if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Security Logging and Monitoring Failures"
                                    let sec_log=sec_log+1
                                fi
                            fi
                        # fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            # echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                            # if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b|\[\b$var\b|\[ \b$var\b"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -q "int\(\b$var\b|int\( \b$var\b"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/int($var/int(escape($var)/g" | sed "s/int( $var/int(escape($var)/g" )
                                            #cng_line=$(echo $cng_line | sed "s/int($var/INT(ESCAPE($var)/g" | sed "s/int( $var/INT(ESCAPE($var)/g" )
                                            #add_remediation 110 $var
                                            #add_remediation 129 $var
                                            add_remediation 125
                                        else
                                            #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" | sed "s/\[$var/\[escape($var)/g" | sed "s/\[ $var/\[ escape($var)/g" )
                                            #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" | sed "s/\[$var/\[ESCAPE($var)/g" | sed "s/\[ $var/\[ ESCAPE($var)/g" )
                                            #add_remediation 104 $var
                                            #add_remediation 111 $var
                                            #add_remediation 129 $var
                                            add_remediation 125
                                        fi
                                        modify=1;
                                    else
                                        echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)|\b$var\b\]|\b$var\b \]"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/$var]/escape($var)]/g" |sed "s/$var ]/escape($var) ]/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                            #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/$var]/ESCAPE($var)]/g" |sed "s/$var ]/ESCAPE($var) ]/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                            #add_remediation 105 $var
                                            #add_remediation 112 $var
                                            #add_remediation 106 $var
                                            #add_remediation 129 $var
                                            add_remediation 125
                                            modify=1;
                                        fi
                                    fi
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"
                                        let inj=inj+1
                                    fi
                                    if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Security Logging and Monitoring Failures"
                                        let sec_log=sec_log+1
                                    fi
                                fi
                            # fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                # echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                # if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                        #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                        #add_remediation 107 $var
                                        #add_remediation 113 $var
                                        #add_remediation 129 $var
                                        add_remediation 125
                                        modify=1;
                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
                                        fi
                                        if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Security Logging and Monitoring Failures"
                                            let sec_log=sec_log+1
                                        fi
                                    fi
                                # fi
                            fi  
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 7"


        #RULE 8: var is the name of the variable before = ldap3.Server()
        num_occ=$(echo $line | awk -F "ldap3.Server\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "ldap3.Server\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "ldap3.Server\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi 
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/ldap3.Server($var)/ldap3.Server()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/ldap3.Server($var/ldap3.Server(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/ldap3.Server(\\\\\"$var\\\\\", $var/ldap3.Server(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "ldap3.Server\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo "$new_line" |awk -F"ldap3.Server\\\(" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
            fi

            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo "RULE 8 - FIRST CHECK"
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\($var||escape_rdn\( $var"
                    if [ $? -eq 0 ]; then
                        #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                        #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                        add_remediation 102 $var
                        add_remediation 129 $var
                        modify=1;
                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Injection"                        
                            let inj=inj+1
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                        if [ $? -eq 0 ]; then
                            #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                            #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                            add_remediation 103 $var
                            add_remediation 129 $var
                            modify=1;
                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Injection"
                                let inj=inj+1
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                    #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                    add_remediation 104 $var
                                    add_remediation 129 $var
                                    modify=1;
                                else
                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                        #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                        add_remediation 105 $var
                                        add_remediation 106 $var
                                        add_remediation 129 $var
                                        modify=1;
                                    fi
                                fi
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                    #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                    add_remediation 107 $var
                                    add_remediation 113 $var
                                    add_remediation 129 $var
                                    modify=1;
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection" 
                                        let inj=inj+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 8"


        #RULE 9: var is the name of the variable before = ldap_connection.search_s()
        num_occ=$(echo $line | awk -F "ldap_connection.search_s\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "ldap_connection.search_s\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "ldap_connection.search_s\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi 
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/ldap_connection.search_s($var)/ldap_connection.search_s()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/ldap_connection.search_s($var/ldap_connection.search_s(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/ldap_connection.search_s(\\\\\"$var\\\\\", $var/ldap_connection.search_s(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "ldap_connection.search_s\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo "$new_line" |awk -F"ldap_connection.search_s\\\(" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
            fi
        
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                    if [ $? -eq 0 ]; then
                        #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                        #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                        add_remediation 102 $var
                        add_remediation 129 $var
                        modify=1;
                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Injection"       
                            let inj=inj+1
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                        if [ $? -eq 0 ]; then 
                            #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                            #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                            add_remediation 103 $var
                            add_remediation 129 $var
                            modify=1;
                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Injection"       
                                let inj=inj+1
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                    #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                    add_remediation 104 $var
                                    add_remediation 129 $var
                                    modify=1;
                                else
                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                        #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                        add_remediation 105 $var
                                        add_remediation 106 $var
                                        add_remediation 129 $var
                                        modify=1;
                                    fi
                                fi
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"       
                                    let inj=inj+1
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                    #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                    add_remediation 107 $var
                                    add_remediation 113 $var
                                    add_remediation 129 $var
                                    modify=1;
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"       
                                        let inj=inj+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 9"

        #RULE 10: if exists a the following pattern: = request.args.get[] and == var
        echo $line | grep -q "request.args.get\[.*==[^a-z]*[a-z]*[^a-z]"
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #parameters=$(echo $line | awk -F 'request.args.get\\[' '{print $2}' | awk -F  '\\]' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/request.args.get\[$parameters\]/escape[request.args.get[$parameters]]/g" | sed "s/request.args.get\[$parameters \]/escape[request.args.get[$parameters]]/g" )
                    #cng_line=$(echo $cng_line | sed "s/request.args.get\[$parameters\]/ESCAPE[REQUEST.ARGS.GET[$parameters]]/g" | sed "s/request.args.get\[$parameters \]/ESCAPE[REQUEST.ARGS.GET[$parameters]]/g" )
                    add_remediation 114 
                    modify=1;
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Broken Access Control"
                        let bac=bac+1
                    fi
                fi
            fi
        fi
        # echo "rule 10"


        #RULE 11: if exists a the following pattern: = urlparse()
        num_occ=$(echo $line | awk -F "urlparse\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "urlparse\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "urlparse\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi 
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/urlparse($var)/urlparse()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/urlparse($var/urlparse(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/urlparse(\\\\\"$var\\\\\", $var/urlparse(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "urlparse\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo "$new_line" |awk -F "urlparse\\\(" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
            fi
            
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                add_remediation 102 $var
                                add_remediation 129 $var
                                modify=1;
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
                                fi
                            fi
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                    #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                    add_remediation 103 $var
                                    add_remediation 129 $var
                                    modify=1;
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"
                                        let inj=inj+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                            #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                            add_remediation 104 $var
                                            add_remediation 129 $var
                                            modify=1;
                                        else
                                            echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                add_remediation 105 $var
                                                add_remediation 106 $var 
                                                add_remediation 129 $var   
                                                modify=1;
                                            fi
                                        fi
                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                            #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                            add_remediation 107 $var
                                            add_remediation 113 $var
                                            add_remediation 129 $var
                                            modify=1;
                                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Injection"
                                                let inj=inj+1
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 11"

        #RULE 12: if exists a the following pattern: urlparse(...).function
        echo $line | grep -P -q "urlparse\(.*?\)\.[a-zA-Z]*"
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\(urlparse\(|escape\( urlparse\("
                if [ $? -eq 0 ]; then
                    #parameters=$(echo $line | awk -F 'urlparse\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/urlparse($parameters/escape(urlparse($parameters)/g")
                    #cng_line=$(echo $cng_line | sed "s/urlparse($parameters/ESCAPE(URLPARSE($parameters)/g")
                    add_remediation 115
                    modify=1;
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                fi
            fi
        fi
        # echo "rule 12"


        #RULE 13: if exists a the following pattern: return urlparse(...)
        echo $line | grep -q "return urlparse("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #parameters=$(echo $line | awk -F 'return urlparse\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/return urlparse($parameters/variable = urlparse($parameters) return escape(variable/g" | sed "s/return urlparse($parameters/variable = urlparse($parameters) return escape(variable/g" )
                    #cng_line=$(echo $cng_line | sed "s/return urlparse($parameters/VARIABLE = URLPARSE($parameters) RETURN ESCAPE(VARIABLE/g" | sed "s/return urlparse($parameters/VARIABLE = URLPARSE($parameters) RETURN ESCAPE(VARIABLE/g" )
                   add_remediation 116
                    modify=1;
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                fi
            fi
        fi
        # echo "rule 13"


        #RULE 14: if exists a the following pattern: = session[]
        num_occ=$(echo $line | awk -F "session\\\[" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "session\\\[" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "session\\\[" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi       
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/session\[$var\]/session\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/session\[$var/session\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/session\[\\\\\"$var\\\\\", $var/session\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "session\\\[" '{print $2}' | cut -d\] -f$split- )
            else
                new_line=$(echo $new_line | awk -F"session\\\[" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }' | cut -d\] -f$split- )
            fi

            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                add_remediation 102 $var
                                add_remediation 129 $var
                                modify=1;
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
                                fi
                            fi
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                    #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                    add_remediation 103 $var
                                    add_remediation 129 $var
                                    modify=1;
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"
                                        let inj=inj+1
                                    fi
                                fi
                            fi
                        fi				
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b|\[\b$var\b|\[ \b$var\b"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" | sed "s/\[$var/\[escape($var)/g" | sed "s/\[ $var/\[ escape($var)/g" )
                                            #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" | sed "s/\[$var/\[ESCAPE($var)/g" | sed "s/\[ $var/\[ ESCAPE($var)/g" )
                                            add_remediation 104 $var
                                            add_remediation 111 $var
                                            add_remediation 129 $var
                                            modify=1;
                                        else
                                            echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)|\b$var\b\]|\b$var\b \]"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/$var]/escape($var)]/g" |sed "s/$var ]/escape($var) ]/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/$var]/ESCAPE($var)]/g" |sed "s/$var ]/ESCAPE($var) ]/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                add_remediation 105 $var
                                                add_remediation 106 $var
                                                add_remediation 112 $var
                                                add_remediation 129 $var
                                                modify=1;
                                            fi
                                        fi
                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                            #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                            add_remediation 107 $var
                                            add_remediation 113 $var
                                            add_remediation 129 $var
                                            modify=1;
                                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Injection"
                                                let inj=inj+1
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 14"
        #######################         NEW RULES       ##########################

        #RULE 15: if exists a the following pattern: = request.args.get()
        source_function="(flask\\\.)?request\\\.(args|GET|POST|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\.get\\\("
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi
                
                #check if there are var not strings
                # ************************** THIS SED LINE HAS TO BE UPDATED ******************************
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                #new_line=$(echo $new_line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.files.get($var)/request.files.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.files.get($var/request.files.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.files.get(\\\\\"$var\\\\\", $var/request.files.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                
                source_function_alt="(flask\.)?request\.(args|GET|POST|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\.get\("
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\(/")s
                new_line=$(echo $new_line | sed "s/$substitution\($var\)/$substitution\(\)/g")
                # echo "new line $new_line"
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" -v i="$i" '{print $(i+1)}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)

                fi

                ####	FIRST CHECK -- MOD WITH %, {} and *
                echo $new_line | grep -E -q "\+ *\b$var\b|= *\b$var\b|= *\b$var\b\\\n|\+ *\b$var\b\\\n|% *\b$var\b|[^{]{ *\b$var\b *}"
                if [ $? -eq 0 ]; then
                    #echo "RULE 15 - FIRST CHECK"
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:|if not $var or" #|if not $var" (SE PROBLEMI togliere if not $var or)
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)" #|logging\.error\(.*(\b$var\b).*?\)" #|yaml.safe_load\(.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                # echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var"
                                # if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g" | sed "s/% *$var/% escape($var)/g" | sed "s/{ *$var *}/{escape($var)}/g")
                                        #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g" | sed "s/% *$var/% ESCAPE($var)/g" | sed "s/{ *$var *}/{ESCAPE($var)}/g")
                                        add_remediation 102 $var
                                        add_remediation 106 $var
                                        add_remediation 117 $var
                                        add_remediation 129 $var
                                        modify=1;
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                # fi
                            fi
                        fi
                    fi
                    
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        #echo "RULE 15 - SECOND CHECK"
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:|if not $var or" #|if not $var"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)" #|yaml.safe_load\(.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                        #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )                                                    
                                        add_remediation 103 $var
                                        add_remediation 129 $var
                                        modify=1;
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            #echo "RULE 15 - THIRD CHECK"
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *|if not $var or" #|if not $var"
                            if [ $? -eq 0 ]; then
                                #echo "RULE 15 - THIRD CHECK - 2"
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    #echo "RULE 15 - THIRD CHECK - 3"
                                    echo $new_line | grep -P -v -q "os\.path\.isfile\([^(]*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        #echo "RULE 15 - THIRD CHECK - 4"
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            #echo "RULE 15 - THIRD CHECK - 5"
                                            echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                add_remediation 104 $var
                                                add_remediation 129 $var
                                                modify=1;
                                            else
                                                echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                if [ $? -eq 0 ]; then
                                                    #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                    #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                    add_remediation 105 $var
                                                    add_remediation 106 $var
                                                    add_remediation 129 $var
                                                    modify=1;
                                                fi
                                            fi
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *|if not $var or" #|if not $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)" #|yaml.safe_load\(.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                add_remediation 107 $var
                                                add_remediation 113 $var
                                                add_remediation 129 $var
                                                modify=1;
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 15"

        #RULE 16: if exists a the following pattern: = request.args.get()
        source_function=" *= *(flask\\\.)?request\\\.json"
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else                
                #check if there are var not strings
                # ************************** THIS SED LINE HAS TO BE UPDATED ******************************
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.json($var)/request.json\()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.json($var/request.json(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.json(\\\\\"$var\\\\\", $var/request.json(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" -v i="$i" '{print $(i+1)}' | cut -f$split- )
                else
                    new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -f$split-)

                fi

                ####	FIRST CHECK -- MOD WITH %, {} and *
                echo $new_line | grep -E -q "\+ *\b$var\b|= *\b$var\b|= *\b$var\b\\\n|\+ *\b$var\b\\\n|% *\b$var\b|{ *\b$var\b *}"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g" | sed "s/% *$var/% escape($var)/g" | sed "s/{ *$var *}/{escape($var)}/g")
                                    #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g" | sed "s/% *$var/% ESCAPE($var)/g" | sed "s/{ *$var *}/{ESCAPE($var)}/g")
                                    add_remediation 102 $var
                                    add_remediation 106 $var
                                    add_remediation 117 $var
                                    add_remediation 129 $var
                                    modify=1;
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                        #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )                                                    
                                        add_remediation 103 $var
                                        add_remediation 129 $var
                                        modify=1;
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                add_remediation 104 $var
                                                add_remediation 129 $var
                                                modify=1;
                                            else
                                                echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                if [ $? -eq 0 ]; then
                                                    #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                    #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                    add_remediation 105 $var
                                                    add_remediation 106 $var
                                                    add_remediation 129 $var
                                                    modify=1;
                                                fi
                                            fi
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                add_remediation 107 $var
                                                add_remediation 113 $var
                                                add_remediation 129 $var
                                                modify=1;
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 16"

        #RULE 17: if exists a the following pattern: return request.args.get(...)
        source_function="return (flask\.)?request\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\.get\(" # source function used for grep: escape with \
        #source_function="return (flask\\\.)?request\\\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\.get\\\(" # source function used for awk: escape with \\\
        substitution=$(echo $line | grep -o -E "$source_function") # obtain the specific pattern found by grep and put it in substitution variable
        if [ -n "$substitution" ]; then
            uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]') # change to uppercase for the CNG file
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #substitution_new=$(echo "$substitution" | sed 's/return //') # remove the "return" keyword
                    #uppercase_substitution_new=$(echo $substitution_new | tr '[:lower:]' '[:upper:]')
                    #parameters=$(echo $line | awk -F "$source_function_alt" '{print $2}'|  awk -F  '\\)' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/$substitution$parameters/variable = $substitution_new$parameters) return escape(variable/g" )
                    #cng_line=$(echo $cng_line | sed "s/$substitution$parameters/VARIABLE = $uppercase_substitution_new$parameters) RETURN ESCAPE(VARIABLE/g" )
                    add_remediation 118
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi
        # echo "rule 17"

        #RULE 18: if exists a the following pattern: return request.args.get(...)
        source_function="return (flask\.)?request\.(args|args\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\["
        source_function_alt="return (flask\\\.)?request\\\.(args|args\\\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\["
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        if [ -n "$substitution" ]; then
            uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]')
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #substitution=$(echo "$substitution" | sed 's/\[//')
                    #substitution_new=$(echo "$substitution" | sed 's/return //')
                    #uppercase_substitution_new=$(echo $substitution_new | tr '[:lower:]' '[:upper:]')
                    #parameters=$(echo $line | awk -F "$source_function_alt" '{print $2}'|  awk -F  '\\]' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/$substitution\[$parameters\]/variable = $substitution_new\[$parameters\] return escape(variable)/g" )
                    #cng_line=$(echo $cng_line | sed "s/$substitution\[$parameters\]/VARIABLE = $uppercase_substitution_new\[$parameters\] RETURN ESCAPE(VARIABLE)/g" )
                    add_remediation 119
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi
        # echo "rule 18"

        #RULE 19: if exists a the following pattern: = request.files[]
        #source_function="(flask\.)?request\.(args|args\.get|files|form|GET|POST|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\["
        source_function="(flask\\\.)?request\\\.(args|args\\\.get|files|form|GET|POST|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\["
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            echo $line | grep -E -q "in request\.(form|files|args|GET|POST|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args) *:"
            if [ $? -eq 0 ]; then
                break
            fi
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 
                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get\[$var\]/request.args.get\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/request.args.get\[$var/request.args.get\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get\[\\\\\"$var\\\\\", $var/request.args.get\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                #new_line=$(echo $new_line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.files\[$var\]/request.files\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.files\[$var/request.files\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.files\[\\\\\"$var\\\\\", $var/request.files\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                                
                source_function_alt="(flask\.)?request\.(args|GET|POST|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\.get\["
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\[/")s
                new_line=$(echo $new_line | sed "s/$substitution\[$var\]/$substitution\[\]/g")
                # echo "new line $new_line"
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\] -f$split- )
                else
                    new_line=$(echo $new_line | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }' | cut -d\] -f$split- )
                fi
                # ####	FIRST CHECK - MOD WITH %
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n|% *\b$var\b"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if .*endswith\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "in request\.(form|files|args|GET|POST) *:"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|os.path.abspath\(.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)" #|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g" | sed "s/% *$var/% escape($var)/g")
                                        #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g"| sed "s/% *$var/% ESCAPE($var)/g")
                                        add_remediation 102 $var
                                        add_remediation 106 $var
                                        add_remediation 129 $var
                                        modify=1;
                                        if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Insecure Design"
                                            let ins_des=ins_des+1
                                        fi
                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if .*endswith\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "in request\.(form|files|args|GET|POST) *:" # grep -v -q "in request.form:|in request.form :"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|os.path.abspath\(.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)" #|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            add_remediation 103 $var
                                            add_remediation 129 $var
                                            modify=1;
                                            if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Insecure Design"
                                                let ins_des=ins_des+1
                                            fi
                                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Injection"
                                                let inj=inj+1
                                            fi
                                        fi
                                    fi
                                fi
                            fi		
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if .*endswith\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "in request\.(form|files|args|GET|POST) *:" # grep -v -q "in request.form:|in request.form :"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|os.path.abspath\(.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)" #|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    add_remediation 104 $var
                                                    add_remediation 129 $var
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        add_remediation 105 $var
                                                        add_remediation 106 $var
                                                        add_remediation 129 $var
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Insecure Design"
                                                    let ins_des=ins_des+1
                                                fi
                                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Injection"
                                                    let inj=inj+1
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if .*endswith\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "in request\.(form|files|args|GET|POST) *:" # grep -v -q "in request.form:|in request.form :"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|os.path.abspath\(.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)" #|try:.*(\b$var\b).*?\)"
                                            if [ $? -eq 0 ]; then
                                                if [ $? -eq 0 ]; then
                                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                                    if [ $? -eq 0 ]; then
                                                        #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                        #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                        add_remediation 107 $var
                                                        add_remediation 113 $var
                                                        add_remediation 129 $var
                                                        modify=1;
                                                        if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                            vuln="$vuln, Insecure Design"
                                                            let ins_des=ins_des+1
                                                        fi
                                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                            vuln="$vuln, Injection"
                                                            let inj=inj+1
                                                        fi
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 19"

        #RULE 20: if exists a the following pattern: return request.get_data(...)
        source_function="return (flask\.)?request\.(get|urlopen|read|get_data|get_json|from_values)\("
        #source_function="return (flask\\\.)?request\\\.(get|urlopen|read|get_data|get_json|from_values)\\\("
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        if [ -n "$substitution" ]; then
            #uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]')
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #substitution_new=$(echo "$substitution" | sed 's/return //')
                    #uppercase_substitution_new=$(echo $substitution_new | tr '[:lower:]' '[:upper:]')
                    #parameters=$(echo $line | awk -F "$source_function_alt" '{print $2}'|  awk -F  '\\)' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/$substitution$parameters/variable = $substitution_new$parameters) return escape(variable/g" )
                    #cng_line=$(echo $cng_line | sed "s/$substitution$parameters/VARIABLE = $uppercase_substitution_new$parameters) RETURN ESCAPE(VARIABLE/g" )
                    add_remediation 120
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi
        # echo "rule 20"

        #RULE 21: if exists a the following pattern: = request.get_data() or request.read() or request.urlopen()
        source_function=" *= *(flask\\\.)?request\\\.(get|urlopen|read|get_data|get_json|from_values)\\\("
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                #check if there are var not strings
                # ************************** THIS SED LINE HAS TO BE UPDATED ******************************
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                source_function_alt="(flask\.)?request\.(get|urlopen|read|get_data|get_json|from_values)\("
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\(/")s
                new_line=$(echo $new_line | sed "s/$substitution\($var\)/$substitution\(\)/g")
                
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(" #|logging\.error\(.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                    #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                    add_remediation 102 $var
                                    add_remediation 129 $var
                                    modify=1;
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(" #|logging\.error\(.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                        #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )                                                    
                                        add_remediation 103 $var
                                        add_remediation 129 $var
                                        modify=1;
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(" #|logging\.error\(.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                add_remediation 104 $var
                                                add_remediation 129 $var
                                                modify=1;
                                            else
                                                echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                if [ $? -eq 0 ]; then
                                                    #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                    #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                    add_remediation 105 $var
                                                    add_remediation 106 $var
                                                    add_remediation 129 $var
                                                    modify=1;
                                                fi
                                            fi
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(" #|logging\.error\(.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                add_remediation 107 $var
                                                add_remediation 113 $var
                                                add_remediation 129 $var
                                                modify=1;
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 21"

        #RULE 22: if exists a the following pattern: = os.environ.get() or = json.loads()
        source_function=" *= *os\\\.environ\\\.get\\\("
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                #check if there are var not strings
                # ************************** THIS SED LINE HAS TO BE UPDATED ******************************
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi
                source_function_alt=" *= *os\.environ\.get\("
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\(/")s
                new_line=$(echo $new_line | sed "s/$substitution\($var\)/$substitution\(\)/g")

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                    #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                    add_remediation 102 $var
                                    add_remediation 129 $var
                                    modify=1;
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                        #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )                                                    
                                        add_remediationq 103 $var
                                        modify=1;
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                add_remediation 104 $var
                                                add_remediation 129 $var
                                                modify=1;
                                            else
                                                echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                if [ $? -eq 0 ]; then
                                                    #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                    #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                    add_remediation 105 $var
                                                    add_remediation 106 $var
                                                    add_remediation 129 $var
                                                    modify=1;
                                                fi
                                            fi
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                add_remediation 107 $var
                                                add_remediation 113 $var
                                                add_remediation 129 $var
                                                modify=1;
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 22"

        #RULE 23: if exists a the following pattern: = os.environ.get() or = json.loads()
        source_function="json\\\.loads\\\("
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "requests.get\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 

                #check if there are var not strings
                # ************************** THIS SED LINE HAS TO BE UPDATED ******************************
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi
                source_function_alt="json\.loads\("
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\(/")s
                new_line=$(echo $new_line | sed "s/$substitution\($var\)/$substitution\(\)/g")

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                    #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                    add_remediation 102 $var
                                    add_remediation 129 $var
                                    modify=1;
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                        #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )                                                    
                                        add_remediation 103 $var
                                        add_remediation 129 $var
                                        modify=1;
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                add_remediation 104 $var
                                                add_remediation 129 $var
                                                modify=1;
                                            else
                                                echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                if [ $? -eq 0 ]; then
                                                    #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                    #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                    add_remediation 105 $var
                                                    add_remediation 106 $var
                                                    add_remediation 129 $var
                                                    modify=1;
                                                fi
                                            fi
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                add_remediation 107 $var
                                                add_remediation 113 $var
                                                add_remediation 129 $var
                                                modify=1;
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 23"

        #RULE 24: if exists a the following pattern: def SOMETHING(var1,var2,...,varn): 
        source_function="def [[:alnum:]_]+\\\(" # def SOMETHING(var):
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        num_commas=0;
        num_vars=0;
        while [ $i -le $num_occ ]; do
            let split=i; # if it does not work put -f1 instead of -f$split
            var=$(echo "$line" | awk -F "$source_function" -v i="$i" '{print $(i+1)}'| cut -d\) -f1)
            if [ -z "$var" ]; then
                pass=1;
            else                 
                if [[ "$var" == *","* ]]; then # if there are commas, update the num_commas variable
                    num_commas=$(echo "$var" | tr -cd ',' | wc -c)
                fi
                let num_vars=num_commas+1 # ex: var1,var2 -> one comma and two variables
                j=1
                while [ $j -le $num_vars ]; do
                    let split_part=j
                    let split_part=split_part+1
                    var_part=$(echo "$var" | awk -v j="$j" -F, '{print $j}' | cut -d',' -f$split_part-) # take j-th variable
                    #check if there are var not strings
                    # ************************** THIS SED LINE HAS TO BE UPDATED ******************************
                    new_line=$(echo $line | sed "s/$var_part(/func(/g"  | sed "s/SELECT $var_part:/ /g" | sed "s/SELECT $var_part :/ /g" | sed "s/def $var_part(/def func(/g" | sed "s/$var_part =/ =/g" | sed "s/$var_part=/ =/g" | sed "s/request.args.get($var_part)/request.args.get()/g" | sed "s/'$var_part '/ /g" | sed "s/\"$var_part/ /g" | sed "s/\" $var_part/ /g" | sed "s/$var_part\"/ /g" |  sed "s/$var_part\", $var_part\"/ /g" | sed "s/$var_part\", $var_part/ /g" | sed "s/$var_part \"/ /g"| sed "s/'$var_part'/ /g" | sed "s/request.args.get($var_part/request.args.get(/g" | sed "s/\\\\\"$var_part\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var_part\\\\\", $var_part/request.args.get(/g" | sed "s/$var_part =()/ /g" | sed "s/$var_part()/ /g" )
                    let split=i;
                    #let split=split+1;
                    if [ $num_occ -eq 1 ]; then
                        new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f2- )
                    else
                        new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                    fi
                    rule1="'<.*href.*'.*\b$var_part\b" # HTML RULE
                    rule2="os\.system\(.*(\b$var_part\b).*?\)|sh\.grep\(.*(\b$var_part\b).*?\)|subprocess\.(run|call|capture_output)\(.*(\b$var_part\b).*?\)|_xxsubinterpreters\.run_string\(.*(\b$var_part\b).*?\)|DYNAMO_CLIENT\.scan\(.*(\b$var_part\b).*?\)|console\.push\(.*(\b$var_part\b).*?\)|re\.sub\(.*(\b$var_part\b).*?\)" # os functions rule
                    rule3="\.execute\(.*(\b$var_part\b).*?\)"
                    echo $new_line | grep -P -q "($rule1|$rule2|$rule3)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var_part\b).*?\], check=True|subprocess.run\(.*(\b$var_part\b).*?\], check =True|subprocess.run\(.*(\b$var_part\b).*?\], check= True|subprocess.run\(.*(\b$var_part\b).*?\], check = True|subprocess.run\(.*(\b$var_part\b).*?\],check=True|subprocess.run\(.*(\b$var_part\b).*?\],check =True|subprocess.run\(.*(\b$var_part\b).*?\],check= True|subprocess.run\(.*(\b$var_part\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var_part\b).*?\)|try:.*(\b$var_part\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "escape\( *$var_part *\)|escape_filter_chars\( *$var_part *\)|escape_rdn\( *$var_part"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                        if [ $? -eq 0 ]; then
                                            #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                            #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                            add_remediation 104 $var
                                            add_remediation 129 $var
                                            modify=1;
                                        else
                                            echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                add_remediation 105 $var
                                                add_remediation 106 $var
                                                add_remediation 129 $var
                                                modify=1;
                                            fi
                                        fi
                                        if [ $inj -eq 0 ]; then # Toggle the category var_partiable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
                                        fi
                                    fi
                                fi
                            fi 
                        fi
                    fi
                    let j=j+1
                done
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 24"


        #RULE 25: if exists a the following pattern: (... + request.args[...])
        source_function="\+ *(flask\.)?request\.(args|args\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\["
        source_function_alt="\\\+ *(flask\\\.)?request\\\.(args|args\\\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\["
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        #if [ $? -eq 0 ]; then
        if [ -n "$substitution" ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\(|os\.path\.isfile\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #substitution=$(echo "$substitution" | sed 's/\+ //')
                    #substitution=$(echo "$substitution" | sed 's/\[//')
                    #uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]')
                    #parameters=$(echo $line | awk -F "$source_function_alt" '{print $2}'|  awk -F  '\\]' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/$substitution\[$parameters\]/escape\($substitution\[$parameters\]\)/g" )
                    #cng_line=$(echo $cng_line | sed "s/$substitution\[$parameters\]/ESCAPE\($uppercase_substitution\[$parameters\]\)/g" )
                    add_remediation 121
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi
        # echo "rule 25"

        #RULE 26: if exists a the following pattern: (... + request.args.get(...))
        source_function="\+ *(flask\.)?request\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\.get\("
        source_function_alt="\\\+ *(flask\.)?request\\\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\.get\\\("
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        #if [ $? -eq 0 ]; then
        if [ -n "$substitution" ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\(|os\.path\.isfile\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #substitution=$(echo "$substitution" | sed 's/\+ //')
                    #uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]')
                    #parameters=$(echo $line | awk -F "$source_function_alt" '{print $2}'|  awk -F  '\\)' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/$substitution\($parameters\)/escape\($substitution$parameters\)/g" )
                    #cng_line=$(echo $cng_line | sed "s/$substitution\($parameters\)/ESCAPE\($uppercase_substitution$parameters\)/g" )
                    add_remediation 122
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi
        # echo "rule 26"


        #RULE 27: if exists a the following pattern: = '{}'.format(request.form)
        source_function="'\\\{\\\}'.format\\\((flask\\\.)?request\\\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\["
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi
                
                #check if there are var not strings
                # ************************** THIS SED LINE HAS TO BE UPDATED ******************************
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\] -f$split- )
                else
                    new_line=$(echo $new_line | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }' | cut -d\] -f$split- )
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    #rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                    #cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                    add_remediation 102 $var
                                    add_remediation 129 $var
                                    modify=1;
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        #rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                        #cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )                                                    
                                        add_remediation 103 $var
                                        add_remediation 129 $var
                                        modify=1;
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                #cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                add_remediation 104 $var
                                                add_remediation 129 $var
                                                modify=1;
                                            else
                                                echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                if [ $? -eq 0 ]; then
                                                    #rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                    #cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                    add_remediation 105 $var
                                                    add_remediation 106 $var
                                                    add_remediation 129 $var
                                                    modify=1;
                                                fi
                                            fi
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                #rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                #cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                add_remediation 107 $var
                                                add_remediation 113 $var
                                                add_remediation 129 $var
                                                modify=1;
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 27"
        
        #RULE 28: if exists a the following pattern: ( request.args.get(...))
        source_function="\( *(flask\.)request\.(args|args\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\("
        source_function_alt="\\\( *(flask\\\.)request\\\.(args|args\\\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\("
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        #if [ $? -eq 0 ]; then
        if [ -n "$substitution" ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]')
                    #parameters=$(echo $line | awk -F "$source_function_alt" '{print $2}'|  awk -F  '\\)' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/$substitution$parameters/\(escape\($substitution$parameters\)/g" )
                    #cng_line=$(echo $cng_line | sed "s/$substitution$parameters/\(ESCAPE\($uppercase_substitution$parameters\)/g" )
                    add_remediation 123
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi
        # echo "rule 28"

        #RULE 29: if exists a the following pattern: (... % request.args.get(...))
        source_function="\% *(flask\.)request\.(args|args\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\("
        source_function_alt="\\\% *(flask\\\.)request\\\.(args|args\\\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\("
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        #if [ $? -eq 0 ]; then
        if [ -n "$substitution" ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    #substitution=$(echo "$substitution" | sed 's/% //')
                    #uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]')
                    #parameters=$(echo $line | awk -F "$source_function_alt" '{print $2}'|  awk -F  '\\)' '{print $1}')
                    #rem_line=$(echo $rem_line | sed "s/$substitution\($parameters\)/escape\($substitution$parameters\)/g" )
                    #cng_line=$(echo $cng_line | sed "s/$substitution\($parameters\)/ESCAPE\($uppercase_substitution$parameters\)/g" )
                    add_remediation 124
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi
        # echo "rule 29"
        
        # RULE 13F
        source_function="(locals\\\(|globals\\\()"
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi
                #check if there are var not strings
                # ************************** THIS SED LINE HAS TO BE UPDATED ******************************
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi
                regex="(django\.shortcuts\.)?render\(.*\b$var\b.*\)"
                if  echo "$new_line" | grep -q -E "$regex"; then       
                    modify=2; #NOT MOD
                    if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1;
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        rule1="(django\.shortcuts\.)?render\(.*locals\(\).*\)"
        rule2="(django\.shortcuts\.)?render\(.*globals\(\).*\)"
        regex="($rule1|$rule2)"
        if  echo "$new_line" | grep -q -E "$regex"; then    
            modify=2; #NOT MOD   
            if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                vuln="$vuln, Injection"
                let inj=inj+1;
            fi
        fi
        # echo "rule 13F"

        #RULE 30: detection of Markup()/Markup.unescape() --> use Markup.escape() instead
        echo $line | grep -E -q "Markup\(|Markup\.unescape\("
        if [ $? -eq 0 ]; then
            # rem_line=$(echo $rem_line | sed "s/Markup(/Markup.escape(/g" | sed "s/Markup.unescape(/Markup.escape(/g")
            # cng_line=$(echo $cng_line | sed "s/Markup(/MARKUP.ESCAPE(/g" | sed "s/Markup.unescape(/MARKUP.ESCAPE(/g")
            add_remediation 87
            add_remediation 88
            modify=1;
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi
        # echo "rule 30"

        #RULE 31: detection of function(... var = input() ...)
        regex="\(.*= *input\(\).*\)"
        echo "$line" | grep -E -q -i "$regex"
        if  [ $? -eq 0 ]; then   
            #rem_line=$(echo $rem_line | sed "s/= input()/= escape(input())/g" | sed "s/=input()/=escape(input())/g")
            #cng_line=$(echo $cng_line | sed "s/= input()/= ESCAPE(INPUT())/g" | sed "s/=input()/=ESCAPE(INPUT())/g")
            add_remediation 125
            modify=1;
            if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                vuln="$vuln, Injection"
                let inj=inj+1;
            fi
        fi
        # echo "rule 31"

        #RULE 32: detection of csv
        regex="(import csv|csv\.writer)"
        echo "$line" | grep -E -q -i "$regex"
        if  [ $? -eq 0 ]; then   
            # rem_line=$(echo $rem_line | sed "s/import csv/import defusedcsv/g" | sed "s/=csv.writer(/=defusedcsv.writer(/g" | sed "s/= csv.writer(/= defusedcsv.writer(/g" )
            # cng_line=$(echo $cng_line | sed "s/import csv/IMPORT DEFUSEDCSV/g" | sed "s/=csv.writer(/=DEFUSEDCSV.WRITER(/g" | sed "s/= csv.writer(/= DEFUSEDCSV.WRITER(/g" )           
            add_remediation 85
            add_remediation 86
            modify=1;
            if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                vuln="$vuln, Injection"
                let inj=inj+1;
            fi
        fi
        # echo "rule 32"

        #RULE 33: detection of subprocess.SOMETHING(...) ---> subprocess.run(...,check=True)
        regex="subprocess\.capture_output\(" #|subprocess.call\("
        echo "$line" | grep -E -q -i "$regex"
        if  [ $? -eq 0 ]; then   
            # rem_line=$(echo $rem_line | sed 's/subprocess\.capture_output(\(.*\))/subprocess.run(\1, capture_output=True, check=True, text=True)/g' )
            # cng_line=$(echo $cng_line | sed 's/subprocess\.capture_output(\(.*\))/SUBPROCESS.RUN(\1, CAPTURE_OUTPUT=TRUE, CHECK=TRUE, TEXT=TRUE)/g' )
            
            # rem_line=$(echo $rem_line | sed 's/subprocess\.call(\(.*\))/subprocess.run(\1, check=True)/g' )
            # cng_line=$(echo $cng_line | sed 's/subprocess\.call(\(.*\))/SUBPROCESS.RUN(\1, CHECK=TRUE)/g' )
            add_remediation 89
            modify=1;
            if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                vuln="$vuln, Injection"
                let inj=inj+1;
            fi
        fi
        # echo "rule 33"



        ########        START KNOWN UNSAFE FUNCTIONS            ########
        #RULE 34: detection of yaml.load() function
        echo $line | grep -E -q -i "yaml\.load\("
        if [ $? -eq 0 ]; then
            # rem_line=$(echo $rem_line | sed "s/yaml\.load(/yaml\.safe_load(/g")
            # cng_line=$(echo $cng_line | sed "s/yaml\.load(/YAML\.SAFE_LOAD(/g")
            # Verifica che l'elemento esista nell'array
            
            #test
            #indexToPrint=24
            #patternToPrint="${patterns[$indexToPrint]}"
            #echo "ci sono: $patternToPrint"
            echo $line | grep -E -v -q "yaml\.load\([^,]+,[ ]*Loader=yaml\.SafeLoader\)"
            if [ $? -eq 0 ]; then
                echo $line | grep -E -v -q "yaml\.load\([^,]+,[ ]*Loader=yaml\.FullLoader\)"
                if [ $? -eq 0 ]; then
                    add_remediation 24
                    modify=1;
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection, Software and Data Integrity Failures"
                        let inj=inj+1
                    fi
                fi
            fi
        fi
        # echo "rule 34"



        #RULE 35: detection of eval() function
        echo $line | grep -E -q -i "\(eval\(| eval\("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "def eval\("
            if [ $? -eq 0 ]; then
                # rem_line=$(echo $rem_line | sed "s/eval(/ast.literal_eval(/g")
                # cng_line=$(echo $cng_line | sed "s/eval(/AST.LITERAL_EVAL(/g")
                add_remediation 28  
                modify=1;
                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi
        # echo "rule 35"


        # MOD - CLUSTER 2 + CLUSTER 8
        #RULE 36: detection of exec() function 
        echo $line | grep -E -q -i "exec\(|execv\(|execl\(" 
        if [ $? -eq 0 ]; then
            echo "RULE 36"
            add_remediation 130
            modify=1;
            #modify=2; #NOT MOD
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi
        # echo "rule 36"

        #RULE 37: detection of subprocess() function 
        echo $line | grep -E -q -i "subprocess\..*\(.*shell\s*=\s*True"
        if [ $? -eq 0 ]; then
            add_remediation 92
            modify=1; 
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi
        # echo "rule 37"



        #RULE 38: detection of traceback.format_exc() function without saving output in a variable
        var=$(echo $line | awk -F "traceback.format_exc\\\(" '{print $1}' |  awk '{print $NF}')
        if [ -z "$var" ]; then
                pass=1;
        else
            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "traceback.format_exc\\\(" '{print $1}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $last_char == "=" ]; then
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi            
            fi   
            ### CHECK  
            echo $line | grep -E -q -i "return traceback.format_exc\(\)|print\($var\)|print\($var\)|print\( $var\)|print\($var \)|print\( $var \)"
            if [ $? -eq 0 ]; then                
                # rem_line=$(echo $rem_line | sed "s/print($var)/ /g" | sed "s/print( $var)/ /g" | sed "s/print($var )/ /g" | sed "s/print( $var )/ /g" | sed "s/return traceback.format_exc/ trace_var = traceback.format_exc/g")
                # cng_line=$(echo $cng_line | sed "s/print($var)/ /g" | sed "s/print( $var)/ /g" | sed "s/print($var )/ /g" | sed "s/print( $var )/ /g" | sed "s/return traceback.format_exc/ TRACE_VAR = TRACEBACK.FORMAT_EXC/g")
                add_remediation 30
                modify=1;
                if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Insecure Design"
                    let ins_des=ins_des+1
                fi
            fi
        fi
        # echo "rule 38"


        #RULE 39: detection of run(debug=True) function
        #echo $line | grep -E -q -i "run\(debug=True\)|.run\(debug=True\)|run\( debug=True \)|.run\( debug=True \)|run\( debug=True\)|.run\( debug=True\)|run\(debug=True \)|.run\(debug=True \)"
        echo $line | grep -E -q -i "\.run\s*\(\s*.*?debug\s*=\s*True.*?\)"

        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]run("
            if [ $? -eq 0 ]; then
                # rem_line=$(echo $rem_line | sed "s/(debug=True/(debug=True, use_debugger=False, use_reloader=False/g")
                # cng_line=$(echo $cng_line | sed "s/(debug=True/(DEBUG=TRUE, USE_DEBUGGER=FALSE, USE_RELOADER=FALSE/g")
                add_remediation 29
                modify=1;
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi
        # echo "rule 39"


        #RULE 40: detection of ftplib.FTP() function
        echo $line | grep -E -q -i "ftplib.FTP\(|FTP\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]FTP("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -i -q " FTP()"
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/ftplib.FTP(/ftplib.FTP_TLS(/g")
                    # cng_line=$(echo $cng_line | sed "s/ftplib.FTP(/FTPLIB.FTP_TLS(/g")
                    add_remediation 31
                    add_remediation 32
                    add_remediation 33
                    modify=1;
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi
        # echo "rule 40"



        #RULE 41: detection of smtplib.SMTP() function
        echo $line | grep -E -q -i "smtplib.SMTP\(|SMTP\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]SMTP("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -i -q " SMTP()"
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/smtplib.SMTP(/smtplib.SMTP_SSL(/g")
                    # cng_line=$(echo $cng_line | sed "s/smtplib.SMTP(/SMTPLIB.SMTP_SSL(/g")
                    add_remediation 34
                    modify=1;
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi                  
                fi
            fi
        fi
        # echo "rule 41"



        #RULE 42: detection of hashlib.sha256() function
        echo $line | grep -E -q -i "hashlib.sha256\(|sha256\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]sha256("
            if [ $? -eq 0 ]; then
            echo $line | grep -v -i -q " sha256("
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/hashlib.sha256(/hashlib.sha512(/g" | sed "s/sha256(/sha512(/g")
                    # cng_line=$(echo $cng_line | sed "s/hashlib.sha256(/HASHLIB.SHA512(/g" | sed "s/sha256(/SHA512(/g")
                    add_remediation 35
                    add_remediation 36
                    modify=1;
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi
        # echo "rule 42"



        #RULE 43: detection of DSA.generate() function with value less (or equal) than 1024
        echo $line |  grep -E -i -q "DSA\.generate\(|DSA\.import_key\(|DSA\.construct\("
        if [ $? -eq 0 ]; then
            echo $line |  grep -E -i -q "DSA\.construct\("
            if [ $? -eq 0]; then
                add_remediation 136
            fi
            add_remediation 37
            add_remediation 134
            add_remediation 135
            #value=$(echo $line | awk -F 'DSA.generate\\(' '{print $2}' | awk -F  ')' '{print $1}')
            # rem_line=$(echo $rem_line | sed "s/DSA.generate($value/DSA.generate(2048/g" | sed "s/DSA.generate( $value/DSA.generate(2048/g")
            # cng_line=$(echo $cng_line | sed "s/DSA.generate($value/DSA.GENERATE(2048/g" | sed "s/DSA.generate( $value/DSA.GENERATE(2048/g")

            modify=1;
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi
        # echo "rule 43"



        #RULE 44: detection of DES.new() function
        echo $line | grep -q -i " DES.new("
        if [ $? -eq 0 ]; then
            # rem_line=$(echo $rem_line | sed "s/DES.new(/sha512.new(/g" )
            # cng_line=$(echo $cng_line | sed "s/DES.new(/SHA512.NEW(/g" )
            add_remediation 38
            modify=1;
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi
        # echo "rule 44"


        #RULE 45: detection of ssl.wrap_socket() function
        echo $line | grep -q -i "ssl.wrap_socket("
        if [ $? -eq 0 ]; then
            # rem_line=$(echo $rem_line | sed "s/ssl.wrap_socket(/SSLContext.wrap_socket(/g")
            # cng_line=$(echo $cng_line | sed "s/ssl.wrap_socket(/SSLCONTEXT.WRAP_SOCKET(/g")
            add_remediation 39
            modify=1;
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi
        # echo "rule 45"


        #RULE 46: detection of hashlib.md5() function
        echo $line | grep -E -q -i "hashlib.md5\(|md5\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]md5("
            if [ $? -eq 0 ]; then
                # rem_line=$(echo $rem_line | sed "s/hashlib.md5(/hashlib.sha512(/g" | sed "s/md5(/sha512(/g")
                # cng_line=$(echo $cng_line | sed "s/hashlib.md5(/HASHLIB.SHA512(/g" | sed "s/md5(/SHA512(/g")
                add_remediation 40
                add_remediation 41
                modify=1;
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi
        # echo "rule 46"



        #RULE 47: detection of hashlib.sha1() function
        echo $line | grep -E -q -i "hashlib.sha1\(|sha1\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]sha1("
            if [ $? -eq 0 ]; then
                # rem_line=$(echo $rem_line | sed "s/hashlib.sha1(/hashlib.sha512(/g" | sed "s/sha1(/sha512(/g")
                # cng_line=$(echo $cng_line | sed "s/hashlib.sha1(/HASHLIB.SHA512(/g" | sed "s/sha1(/SHA512(/g")
                add_remediation 42
                add_remediation 43
                modify=1;
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi
        # echo "rule 47"



        #RULE 48-old: detection of algorithms.AES() function
#        new_line=$(echo $line | sed "s/AES(__name__)/ /g" | sed "s/def AES(/def func(/g" | sed "s/return AES():/ /g" | sed "s/AES =/ /g" | sed "s/AES=/ /g" )
#        echo $new_line | grep -E -q -i "algorithms.AES\(|AES\("
#        if [ $? -eq 0 ]; then
#           echo $new_line | grep -v -q "[a-zA-Z0-9]AES("
#            if [ $? -eq 0 ]; then
#                # rem_line=$(echo $rem_line | sed "s/algorithms.AES/algorithms.sha512/g" | sed "s/AES(/sha512(/g" )
#                # cng_line=$(echo $cng_line | sed "s/algorithms.AES/ALGORITHMS.SHA512/g" | sed "s/AES(/SHA512(/g" )
#                modify=1;
#                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
#                    vuln="$vuln, Cryptographic Failures"
#                    let crypto=crypto+1
#                fi
#            fi
#        fi


        #RULE 48-new: detection of modes.ECB() function OR macro AES.MODE_ECB
        echo $line | grep -E -q -i "modes\.ECB\(|AES\.MODE_ECB"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]ECB("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def ECB("
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/AES.MODE_CBC/AES.MODE_GCM/g" | sed "s/modes.CBC/modes.GCM/g" )
                    # cng_line=$(echo $cng_line | sed "s/AES.MODE_CBC/AES.MODE_GCM/g" | sed "s/modes.CBC/MODES.GCM/g" )
                    add_remediation 45
                    add_remediation 47
                    modify=1;
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi
        # echo "rule 48"


        #RULE 49: detection of modes.CBC() function OR macro AES.MODE_CBC
        echo $line | grep -E -q -i "modes.CBC\(|AES.MODE_CBC"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]CBC("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def CBC("
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/AES.MODE_CBC/AES.MODE_GCM/g" | sed "s/modes.CBC/modes.GCM/g" )
                    # cng_line=$(echo $cng_line | sed "s/AES.MODE_CBC/AES.MODE_GCM/g" | sed "s/modes.CBC/MODES.GCM/g" )
                    add_remediation 44
                    add_remediation 46
                    modify=1;
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi
        # echo "rule 49"




        #RULE 50: detection of random.randint() function
        echo $line | grep -E -q -i "random.randint\(|randint\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]randint("
            if [ $? -eq 0 ]; then
                # rem_line=$(echo $rem_line | sed "s/random.randint(/my_secure_rng = secrets.SystemRandom() \\\n my_secure_rng.randrange(/g" | sed "s/import random/import secrets/g")
                # cng_line=$(echo $cng_line | sed "s/random.randint(/MY_SECURE_RNG = SECRETS.SYSTEMRANDOM() \\\n MY_SECURE_RNG.RANDRANGE(/g" | sed "s/import random/IMPORT SECRETS/g")
                add_remediation 48
                add_remediation 49
                modify=1;
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi      
            fi
        fi
        # echo "rule 50"



        #RULE 51: detection of random.choice() function
        echo $line | grep -E -q -i "random.choice\(|choice\(|random.choices\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]choice("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "secrets.choice("
                if [ $? -eq 0 ]; then
                    echo $line | grep -v -q "secrets\."
                    if [ $? -eq 0 ]; then
                        # rem_line=$(echo $rem_line | sed "s/random.choice(/secrets.choice(/g" | sed "s/random.choices(/secrets.choice(/g" | sed "s/import random/import secrets/g")
                        # cng_line=$(echo $cng_line | sed "s/random.choice(/SECRETS.CHOICE(/g" | sed "s/random.choices(/SECRETS.CHOICE(/g" | sed "s/import random/IMPORT SECRETS/g")
                        add_remediation 49
                        add_remediation 50
                        add_remediation 51
                        modify=1;
                        if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Cryptographic Failures"
                            let crypto=crypto+1
                        fi
                    fi
                fi

            fi
        fi
        # echo "rule 51"



        #RULE 52: detection of random.getrandbits() function
        echo $line | grep -E -q -i "random.getrandbits\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]getrandbits("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "secrets\."
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/random.getrandbits(/secrets.randbits(/g" | sed "s/import random/import secrets/g")
                    # cng_line=$(echo $cng_line | sed "s/random.getrandbits(/SECRETS.RANDBITS(/g" | sed "s/import random/IMPORT SECRETS/g")
                    add_remediation 49
                    add_remediation 52
                    modify=1;
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi
        # echo "rule 52"



        #RULE 53: detection of jwt.process_jwt() function
        echo $line | grep -E -q -i "jwt.process_jwt\([a-zA-Z0-9]*[^,]\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]process_jwt("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "verify_jwt("
                if [ $? -eq 0 ]; then
                    token=$(echo $line | awk -F 'jwt.process_jwt\\(' '{print $2}' | awk -F  ')' '{print $1}')
                    # rem_line=$(echo $rem_line | sed "s/jwt.process_jwt($token/jwt.process_jwt($token, \"key\", algorithms=[\"HS512\"]/g" | sed "s/jwt.process_jwt( $token/jwt.process_jwt($token, \"key\", algorithms=[\"HS512\"]/g")
                    # cng_line=$(echo $cng_line | sed "s/jwt.process_jwt($token/JWT.PROCESS_JWT($token, \"KEY\", ALGORITHMS=[\"HS512\"]/g" | sed "s/jwt.process_jwt( $token/JWT.PROCESS_JWT($token, \"KEY\", ALGORITHMS=[\"HS512\"]/g")
                    add_remediation 53
                    modify=1;
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi
        # echo "rule 53"



        #RULE 54: detection of mktmp() function
        echo $line | grep -E -q -i "mktemp\(|\.mktemp\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]mktemp("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def mktemp("
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/mktemp(/TemporaryFile(/g")
                    # cng_line=$(echo $cng_line | sed "s/mktemp(/TEMPORARYFILE(/g")
                    add_remediation 54
                    modify=1;
                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Broken Access Control"
                        let bac=bac+1
                    fi
                fi
            fi
        fi
        # echo "rule 54"


        #RULE 55: detection of mktmp() function
        echo $line | grep -E -q -i "mkstemp\(|\.mkstemp\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]mkstemp("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def mkstemp("
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/mktemp(/TemporaryFile(/g")
                    # cng_line=$(echo $cng_line | sed "s/mktemp(/TEMPORARYFILE(/g")
                    add_remediation 54
                    modify=1;
                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Broken Access Control"
                        let bac=bac+1
                    fi
                fi
            fi
        fi
        # echo "rule 54bis"



        #RULE 56: detection of time.clock() function
        echo $line | grep -E -q -i "time.clock\(|clock\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]clock("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def clock("
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/clock(/perf_counter(/g")
                    # cng_line=$(echo $cng_line | sed "s/clock(/PERF_COUNTER(/g")
                    add_remediation 55
                    modify=1;
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                fi
            fi
        fi
        # echo "rule 55"



        #RULE 57: detection of pickle functions
        new_line=$(echo $line | sed "s/import cPickle/ /g" | sed "s/import pickle/ /g" | sed "s/import [a-zA-Z0-9]cPickle/ /g" | sed "s/import _pickle/ /g" | sed "s/pickle.this/ /g" )
        echo $new_line | grep -E -q -i "pickle\.loads\(|pickle\.load\(|pickle\.dump\(|pickle\.dumps\(|pickle\.Unpickler\(|cPickle\.loads\(|cPickle\.load\(|cPickle\.dump\(|cPickle\.dumps\(|cPickle\.Unpickler\("
        if [ $? -eq 0 ]; then
            echo $new_line | grep -v -q "\b[a-zA-Z0-9]pickle\b"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -v -q "\b[a-zA-Z0-9]cPickle\b"
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/\bpickle\.\b/pickle_secure./g" | sed "s/\bcPickle\.\b/pickle_secure./g" | sed "s/import pickle/import pickle_secure/g" | sed "s/import cPickle/import pickle_secure/g" )
                    # cng_line=$(echo $cng_line | sed "s/\bpickle\.\b/PICKLE_SECURE./g" | sed "s/\bcPickle\.\b/PICKLE_SECURE./g" | sed "s/import pickle/IMPORT PICKLE_SECURE/g" | sed "s/import cPickle/IMPORT PICKLE_SECURE/g" )
                    add_remediation 25
                    add_remediation 26
                    add_remediation 27
                    add_remediation 56
                    add_remediation 57
                    add_remediation 58
                    add_remediation 59
                    modify=1;
                    if [ $soft_data -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Software and Data Integrity Failures"
                        let soft_data=soft_data+1
                    fi
                fi
            fi
        fi
        # echo "rule 56"



        #RULE 58: detection of xml.sax.make_parser() function
        echo $line | grep -E -q -i "xml.sax.make_parser\(|xml\.sax\."
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]xml\.sax\."
            if [ $? -eq 0 ]; then
                echo $line | grep -E -v -q -i "setFeature\(feature_external_ges, False\)|setFeature\(feature_external_ges,False\)"
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/xml.sax.make_parser/defusedxml.sax.make_parser/g" )
                    # cng_line=$(echo $cng_line | sed "s/xml.sax.make_parser/DEFUSEDXML.SAX.MAKE_PARSER/g" )
                    add_remediation 60
                    #add_remediation 62
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1
                    fi
                fi
            fi
        fi
        # echo "rule 57"

        #RULE 59: detection of assert
        echo $line | grep -E -q -i "\bassert\b| \bassert\b"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]assert"
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "except AssertionError"
                if [ $? -eq 0 ]; then                    
                    #last_char=$(echo "${line: -1}")
                    #if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    #    rem_line=${line:0:$((${#line} - 1))}
                    #elif [ $name_os = "Linux" ]; then #LINUX system
                    #    rem_line=${line::-1}
                    #fi
                    # rem_line="$rem_line \\n except AssertionError as msg: \\n print(msg)"
                    # cng_line="$cng_line \\n EXCEPT ASSERTIONERROR AS MSG: \\n PRINT(MSG)"
                    #rem_line="$rem_line $last_char"
                    add_remediation 63
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1
                    fi
                fi
            fi
        fi
        # echo "rule 58"



        #RULE 60: detection of hashlib.new() function with a single param
        echo $line | grep -q -i "hashlib.new([^a-z]*[a-zA-Z0-9]*[^,][^a-Z]*)"
        if [ $? -eq 0 ]; then
            protocol=$(echo $line | awk -F 'hashlib.new\\(' '{print $2}' | awk -F '\\)' '{print $1}')
            # rem_line=$(echo $rem_line | sed "s/hashlib.new( $protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new($protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new('$protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new(' $protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new( '$protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new( ' $protocol/hashlib.new('sha512', usedforsecurity=True/g")
            # cng_line=$(echo $cng_line | sed "s/hashlib.new( $protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new($protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new('$protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new(' $protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new( '$protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new( ' $protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g")
            add_remediation 64
            modify=1;
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi
        # echo "rule 59"



        #RULE 61: detection of pbkdf2_hmac() function
        echo $line | grep -E -q -i "pbkdf2_hmac\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]pbkdf2_hmac("
            if [ $? -eq 0 ]; then
                protocol=$(echo $line | awk -F 'pbkdf2_hmac\\(' '{print $2}' | awk -F ',' '{print $1}')
                echo $protocol | grep -E -q -i "sha512|sha3_224|sha3_256|sha3_384|sha3_512" #whitelisting
                if [ $? -eq 1 ]; then #are used protocols different form the selected ones
                    # rem_line=$(echo $rem_line | sed "s/pbkdf2_hmac( $protocol/pbkdf2_hmac('sha512'/g" | sed "s/pbkdf2_hmac($protocol/pbkdf2_hmac('sha512'/g" | sed "s/pbkdf2_hmac('$protocol/pbkdf2_hmac('sha512/g" | sed "s/pbkdf2_hmac(' $protocol/pbkdf2_hmac('sha512/g" | sed "s/pbkdf2_hmac( '$protocol/pbkdf2_hmac('sha512/g" | sed "s/pbkdf2_hmac( ' $protocol/pbkdf2_hmac('sha512/g")
                    # cng_line=$(echo $cng_line | sed "s/pbkdf2_hmac( $protocol/PBKDF2_HMAC('SHA512'/g" | sed "s/pbkdf2_hmac($protocol/PBKDF2_HMAC('SHA512'/g" | sed "s/pbkdf2_hmac('$protocol/PBKDF2_HMAC('SHA512/g" | sed "s/pbkdf2_hmac(' $protocol/PBKDF2_HMAC('SHA512/g" | sed "s/pbkdf2_hmac( '$protocol/PBKDF2_HMAC('SHA512/g" | sed "s/pbkdf2_hmac( ' $protocol/PBKDF2_HMAC('SHA512/g")
                    add_remediation 65
                    modify=1;
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi
        # echo "rule 60"



        #RULE 62: detection of parseUDPpacket() function
        echo $line | grep -E -q -i "parseUDPpacket\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]parseUDPpacket("
            if [ $? -eq 0 ]; then
                # rem_line=$(echo $rem_line | sed "s/parseUDPpacket(/parseTCPpacket(/g" | sed "s/parseUDPpacket(/parseTCPpacket(/g" )
                # cng_line=$(echo $cng_line | sed "s/parseUDPpacket(/PARSETCPPACKET(/g" | sed "s/parseUDPpacket(/PARSETCPPACKET(/g" )
                add_remediation 66
                modify=1;
                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi
        # echo "rule 61"



        #RULE 63: detection of os.system(...file.bin...) function
        echo $line | grep -E -q -i "os.system\([^a-z]*[a-z]*\.bin"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]os.system([^a-z]*[a-z]*\.bin"
            if [ $? -eq 0 ]; then
                # rem_line=$(echo $rem_line | sed "s/.bin/.txt/g" )
                # cng_line=$(echo $cng_line | sed "s/.bin/.TXT/g" )
                add_remediation 67
                modify=1;
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi
        # echo "rule 62"



        #RULE 64: detection of os.system() function
        #echo $line | grep -E -q -i "\(exec, \('import os;os\.system\(|\(exec,\('import os;os.system\(|\(exec,\('import os ; os.system\(|\(exec, \('import os ; os.system\("
        echo $line | grep -E -q -i "os\.system\(|os\.popen\("
        if [ $? -eq 0 ]; then
        echo "RULE 64"
            add_remediation 93
            modify=1; #NOT MOD
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi


        #RULE 65: detection of etree.ElementTree library
        echo $line | grep -q -i "etree.ElementTree as ET.*ET\."
        if [ $? -eq 0 ]; then
            # rem_line=$(echo $rem_line | sed "s/etree.ElementTree/defusedxml.ElementTree/g" )
            # cng_line=$(echo $cng_line | sed "s/etree.ElementTree/DEFUSEDXML.ELEMENTTREE/g" )
            add_remediation 61
            add_remediation 62
            modify=1;
            if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Security Misconfiguration"
                let sec_mis=sec_mis+1
            fi
        fi
        # echo "rule 64"



        #RULE 65: detection of GENERIC 'raisePrivilege() function() lowPrivilege()'
        #echo $line | grep -q -i "raisePrivileges().*lowerPrivileges()"
        #if [ $? -eq 0 ]; then
        #    rem_line=$(echo $rem_line | sed "s/raisePrivileges()/ /g" | sed "s/lowerPrivileges()/ /g" )
        #    cng_line=$(echo $cng_line | sed "s/raisePrivileges()/ /g" | sed "s/lowerPrivileges()/ /g" )
        #    modify=1;
        #    if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
        #        vuln="$vuln, Insecure Design"
        #        let ins_des=ins_des+1
        #    fi
        #fi



        #RULE 66: detection of GENERIC 'requests.get(..., verify=False)'
        echo $line | grep -q "requests\..*(.*verify=False"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]requests\."
            if [ $? -eq 0 ]; then
                # rem_line=$(echo $rem_line | sed "s/verify=False/verify=True/g" | sed "s/verify = False/verify=True/g" |sed "s/verify=false/verify=True/g" | sed "s/verify = false/verify=True/g")
                # cng_line=$(echo $cng_line | sed "s/verify=False/VERIFY=TRUE/g" | sed "s/verify = False/VERIFY=TRUE/g" |sed "s/verify=false/VERIFY=TRUE/g" | sed "s/verify = false/VERIFY=TRUE/g")
                add_remediation 68
                modify=1;
                if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Identification and Authentication Failures"
                    let id_auth=id_auth+1
                fi
            fi
        fi
        # echo "rule 66"






        ########            START CONFIGURATION PROBLEM        ########
        #RULE 67: detection of os.chmod() function
        echo $line | grep -E -q -i "os.chmod\(.*, 0000\)|os.chmod\(.*, 0o000\)|os.chmod\(.*, 755)|os.chmod\(.*, 0o755\)|os.chmod\(.*, 777)|os.chmod\(.*, 0o777\)"
        if [ $? -eq 0 ]; then
            # rem_line=$(echo $rem_line | sed "s/0000/600/g" | sed "s/0o400/600/g" | sed "s/128/600/g" )
            # cng_line=$(echo $cng_line | sed "s/0000/600/g" | sed "s/0o400/600/g" | sed "s/128/600/g" )
            add_remediation 98
            modify=1;
            if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Security Misconfiguration"
                let sec_mis=sec_mis+1
            fi
        fi
        # echo "rule 67"



        #RULE 68: detection of response.set_cookie() with plaintext password
        new_line=$(echo $line | sed "s/def set_cookie()/ /g" | sed "s/set_cookie(__name__)/ /g" )
        echo $new_line | grep -E -q -i "\.set_cookie\([^,]*, [a-zA-Z0-9_]*\)|set_cookie\(.*, [a-zA-Z0-9]*\)|\.set_cookie\([^a-z]*[a-zA-Z0-9]*[^a-z]*\)|set_cookie\([^a-z]*[a-zA-Z0-9]*[^a-z]*\)"
        if [ $? -eq 0 ]; then
            echo "RULE 68"
            rule_68=false
            echo $new_line | grep -v -q -i "\.set_cookie(.*,(expires|max_age) *="
            if [ $? -eq 0 ]; then
                echo "RULE 68 - 1"
                # token=$(echo $line | awk -F 'set_cookie\\(' '{print $2}' | awk -F  ')' '{print $1}' )
                # split_token=$(echo $line | awk -F  ',' '{print $2}' | awk -F  ')' '{print $1}')
                # if [ -z "$split_token" ]; then
                #     rem_line=$(echo $rem_line | sed "s/$token/$token, date/g" )
                #     cng_line=$(echo $cng_line | sed "s/$token/$token, DATE/g" )
                # else
                #     rem_line=$(echo $rem_line | sed "s/$split_token/$split_token, date/g" )
                #     cng_line=$(echo $cng_line | sed "s/$split_token/$split_token, DATE/g" )
                # fi
                add_remediation 69
                rule_68=true
                #modify=1;
                #if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                #    vuln="$vuln, Security Misconfiguration"
                #    let sec_mis=sec_mis+1
                #fi
            fi
            echo $new_line | grep -v -q -i "\.set_cookie(.*,httponly *="
            if [ $? -eq 0 ]; then
                echo "RULE 68 - 1"
                # token=$(echo $line | awk -F 'set_cookie\\(' '{print $2}' | awk -F  ')' '{print $1}' )
                # split_token=$(echo $line | awk -F  ',' '{print $2}' | awk -F  ')' '{print $1}')
                # if [ -z "$split_token" ]; then
                #     rem_line=$(echo $rem_line | sed "s/$token/$token, date/g" )
                #     cng_line=$(echo $cng_line | sed "s/$token/$token, DATE/g" )
                # else
                #     rem_line=$(echo $rem_line | sed "s/$split_token/$split_token, date/g" )
                #     cng_line=$(echo $cng_line | sed "s/$split_token/$split_token, DATE/g" )
                # fi
                add_remediation 131
                rule_68=true
            fi
            echo $new_line | grep -v -q -i "\.set_cookie(.*,secure *="
            if [ $? -eq 0 ]; then
                echo "RULE 68 - 1"
                # token=$(echo $line | awk -F 'set_cookie\\(' '{print $2}' | awk -F  ')' '{print $1}' )
                # split_token=$(echo $line | awk -F  ',' '{print $2}' | awk -F  ')' '{print $1}')
                # if [ -z "$split_token" ]; then
                #     rem_line=$(echo $rem_line | sed "s/$token/$token, date/g" )
                #     cng_line=$(echo $cng_line | sed "s/$token/$token, DATE/g" )
                # else
                #     rem_line=$(echo $rem_line | sed "s/$split_token/$split_token, date/g" )
                #     cng_line=$(echo $cng_line | sed "s/$split_token/$split_token, DATE/g" )
                # fi
                add_remediation 132
                rule_68=true
            fi
            echo $new_line | grep -v -q -i "\.set_cookie(.*,samesite *="
            if [ $? -eq 0 ]; then
                echo "RULE 68 - 1"
                # token=$(echo $line | awk -F 'set_cookie\\(' '{print $2}' | awk -F  ')' '{print $1}' )
                # split_token=$(echo $line | awk -F  ',' '{print $2}' | awk -F  ')' '{print $1}')
                # if [ -z "$split_token" ]; then
                #     rem_line=$(echo $rem_line | sed "s/$token/$token, date/g" )
                #     cng_line=$(echo $cng_line | sed "s/$token/$token, DATE/g" )
                # else
                #     rem_line=$(echo $rem_line | sed "s/$split_token/$split_token, date/g" )
                #     cng_line=$(echo $cng_line | sed "s/$split_token/$split_token, DATE/g" )
                # fi
                add_remediation 133
                rule_68=true
            fi            
            #check if rule68 is true
            if [ $rule_68 = true ]; then
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi

        fi
        # echo "rule 68"



        #RULE 69: detection of 'ctx.check_hostname = False' AND 'ctx.verify_mode = ssl.CERT_NONE'
        echo $line | grep -q -i "ssl.create_default_context() .* ctx.verify_mode = ssl.CERT_NONE"
        if [ $? -eq 0 ]; then
            hostname=$(echo $line | awk -F 'check_hostname' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            cert=$(echo $line | awk -F 'verify_mode' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            # rem_line=$(echo $rem_line | sed "s/check_hostname = $hostname/check_hostname = True/g" | sed "s/check_hostname=$hostname/check_hostname=True/g" |  sed "s/check_hostname= $hostname/check_hostname= True/g" |  sed "s/check_hostname =$hostname/check_hostname =True/g" | sed "s/verify_mode = $cert/verify_mode = ssl.CERT_REQUIRED/g" | sed "s/verify_mode=$cert/verify_mode=ssl.CERT_REQUIRED/g" | sed "s/verify_mode= $cert/verify_mode= ssl.CERT_REQUIRED/g" | sed "s/verify_mode =$cert/verify_mode =ssl.CERT_REQUIRED/g")
            # cng_line=$(echo $cng_line | sed "s/check_hostname = $hostname/CHECK_HOSTNAME = TRUE/g" | sed "s/check_hostname=$hostname/CHECK_HOSTNAME=TRUE/g" |  sed "s/check_hostname= $hostname/CHECK_HOSTNAME= TRUE/g" |  sed "s/check_hostname =$hostname/CHECK_HOSTNAME =TRUE/g" | sed "s/verify_mode = $cert/VERIFY_MODE = SSL.CERT_REQUIRED/g" | sed "s/verify_mode=$cert/VERIFY_MODE=SSL.CERT_REQUIRED/g" | sed "s/verify_mode= $cert/VERIFY_MODE= SSL.CERT_REQUIRED/g" | sed "s/verify_mode =$cert/VERIFY_MODE =SSL.CERT_REQUIRED/g")
            add_remediation 70
            add_remediation 71
            modify=1;
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi
        # echo "rule 69"



        #RULE 70: detection of 'ssl._create_unverified_context()'
        echo $line | grep -E -q -i "ssl._create_unverified_context()|ctx._create_unverified_context = True"
        if [ $? -eq 0 ]; then
            # rem_line=$(echo $rem_line | sed "s/ssl._create_unverified_context()/ssl._create_unverified_context() \\\n check_hostname = True \\\n verify_mode =ssl.CERT_REQUIRED/g" )
            # cng_line=$(echo $cng_line | sed "s/ssl._create_unverified_context()/SSL._CREATE_UNVERIFIED_CONTEXT() \\\n CHECK_HOSTNAME = TRUE \\\n VERIFY_MODE =SSL.CERT_REQUIRED/g" )
            add_remediation 72
            add_remediation 73
            modify=1;
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi
        # echo "rule 70"



        #RULE 71: detection of 'ssl._create_stdlib_context()'
        echo $line | grep -q -i "ssl._create_stdlib_context()"
        if [ $? -eq 0 ]; then
            # rem_line=$(echo $rem_line | sed "s/ssl._create_stdlib_context()/ssl._create_stdlib_context(ssl.PROTOCOL_TLS)/g")
            # cng_line=$(echo $cng_line | sed "s/ssl._create_stdlib_context()/SSL._CREATE_STDLIB_CONTEXT(SSL.PROTOCOL_TLS)/g")
            add_remediation 74
            modify=1;
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi
        # echo "rule 71"


        #RULE 72: detection of 'ssl.create_default_context()' AND'ctx.check_hostname = False'
        echo $line | grep -q -i "check_hostname = false"
        if [ $? -eq 0 ]; then
            hostname=$(echo $line | awk -F 'check_hostname' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            # rem_line=$(echo $rem_line | sed "s/check_hostname = $hostname/check_hostname = True/g" | sed "s/check_hostname=$hostname/check_hostname=True/g" |  sed "s/check_hostname= $hostname/check_hostname= True/g" |  sed "s/check_hostname =$hostname/check_hostname =True/g" )
            # cng_line=$(echo $cng_line | sed "s/check_hostname = $hostname/CHECK_HOSTNAME = TRUE/g" | sed "s/check_hostname=$hostname/CHECK_HOSTNAME=TRUE/g" |  sed "s/check_hostname= $hostname/CHECK_HOSTNAME= TRUE/g" |  sed "s/check_hostname =$hostname/CHECK_HOSTNAME =TRUE/g" )
            add_remediation 70
            add_remediation 73
            modify=1;
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi
        # echo "rule 72"



        #RULE 73: detection of SSL.TLSv1_2_METHOD OR SSL.TLSv1_2
        #echo $line | grep -q -i "SSL.TLSv1_2_METHOD|SSL.PROTOCOL_TLSv1_2"
        echo $line | grep -E -q -i "(ssl|SSL)\.(SSLv2|SSLv3|SSLv23|TLSv1|TLSv1_1)_METHOD|ssl\.PROTOCOL_(SSLv2|SSLv3|TLSv1(_1)?)"
        if [ $? -eq 0 ]; then
            #select the higher version of SSL
            # rem_line=$(echo $rem_line | sed "s/SSL.TLSv1_2_METHOD/ssl.PROTOCOL_TLS/g" | sed "s/ssl.TLSv1_2_METHOD/ssl.PROTOCOL_TLS/g")
            # cng_line=$(echo $cng_line | sed "s/SSL.TLSv1_2_METHOD/SSL.PROTOCOL_TLS/g" | sed "s/ssl.TLSv1_2_METHOD/SSL.PROTOCOL_TLS/g")
            add_remediation 75
            add_remediation 76
            modify=1;
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi
        # echo "rule 73"



        #RULE 74: detection of urandom() with value less than 64
        echo $line |  grep -E -i -q "urandom\((0|1|2|4|8|16|32)\)|urandom\( (0|1|2|4|8|16|32) \)|urandom\( (0|1|2|4|8|16|32)\)|urandom\((0|1|2|4|8|16|32) \)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q -i "[a-zA-Z0-9]urandom"
            if [ $? -eq 0 ]; then
                # value=$(echo $line | awk -F 'urandom\\(' '{print $2}' | awk -F '\\)' '{print $1}')
                # rem_line=$(echo $rem_line | sed "s/urandom($value)/urandom(64)/g" | sed "s/urandom( $value )/urandom(64)/g" | sed "s/urandom( $value)/urandom(64)/g" | sed "s/urandom($value )/urandom(64)/g")
                # cng_line=$(echo $cng_line | sed "s/urandom($value)/URANDOM(64)/g" | sed "s/urandom( $value )/URANDOM(64)/g" | sed "s/urandom( $value)/URANDOM(64)/g" | sed "s/urandom($value )/URANDOM(64)/g")
                add_remediation 77
                modify=1;
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi
        # echo "rule 74"



        #RULE 75: detection of 'key_size' less than 2048
        echo $line | grep -E -q -i "key_size=([1-9] |[1-1][0-9][0-9] |[1-1][0-9][0-9][0-9] |204[0-7] )|key_size=([1-9]\\\n |[1-1][0-9][0-9]\\\n |[1-1][0-9][0-9][0-9]\\\n |204[0-7]\\\n )"
        if [ $? -eq 0 ]; then
            #value=$(echo $line | awk -F 'key_size' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            # rem_line=$(echo $rem_line | sed "s/key_size=$value/key_size=2048/g")
            # cng_line=$(echo $cng_line | sed "s/key_size=$value/KEY_SIZE=2048/g")
            add_remediation 78
            modify=1;
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi
        # echo "rule 75"


        #RULE 76: detection of 'jwt.decode(..., verify = False)'
        echo $line | grep -E -q -i "jwt\.decode\(.*verify = False|jwt.decode\(.*verify=False"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]decode("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "([a-zA-Z0-9]verify = False"
                if [ $? -eq 0 ]; then
                    #token=$(echo $line | awk -F 'decode\\(' '{print $2}' | awk -F  ',' '{print $1}')
                    # rem_line=$(echo $rem_line | sed "s/jwt.decode(.*verify = False)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify=False)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify=false)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify = false)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g")
                    # cng_line=$(echo $cng_line | sed "s/jwt.decode(.*verify = False)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify=False)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify=false)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify = false)/JWT.DECODE($token, \"KEY\", ALGORITMHS=[\"HS512\"])/g")
                    add_remediation 79
                    modify=1;
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi
        # echo "rule 76"


        #RULE 77: detection of 'jwt.decode(token)'
        echo $line | grep -E -q -i "jwt\.decode\([a-zA-Z0-9_]*\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]decode("
            if [ $? -eq 0 ]; then
                #token=$(echo $line | awk -F 'decode\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                # rem_line=$(echo $rem_line | sed "s/jwt.decode(.*)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g")
                # cng_line=$(echo $cng_line | sed "s/jwt.decode(.*)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g")
                add_remediation 128
                modify=1;
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi
        # echo "rule 77"



        #RULE 78: detection of 'jwt.decode(token, key, options={\"verify_signature\": False}..)'
        echo $line | grep -q -i "jwt.decode(.*, options={[^a-z]*verify_signature[^a-z]* False"
        if [ $? -eq 0 ]; then
            #token=$(echo $line | awk -F 'decode\\(' '{print $2}' | awk -F  ',' '{print $1}')
            #key=$(echo $line | awk -F 'decode\\(' '{print $2}' | awk -F  ',' '{print $2}' | awk -F  ',' '{print $1}')
            # rem_line=$(echo $rem_line | sed "s/jwt.decode(.*options=.*: False})/jwt.decode($token, \"$key\", algorithms=[\"HS512\"])/g" )
            # cng_line=$(echo $cng_line | sed "s/jwt.decode(.*options=.*: False})/JWT.DECODE($token, \"$key\", ALGORITHMS=[\"HS512\"])/g" )
           add_remediation 80
            modify=1;
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi
        # echo "rule 78"




        #RULE 79: detection of 's.bind(('0.0.0.0', ...))'
        echo $line | grep -P -q -i "\.bind\(\(('0\.0\.0\.0'|'').*?\)\)"
        if [ $? -eq 0 ]; then         
            echo $line | grep -v -q "[a-zA-Z0-9]bind\(\(('0.0.0.0'|''),.*\)\)"
            if [ $? -eq 0 ]; then
                echo "RULE 79"
                # rem_line=$(echo $rem_line | sed "s/0.0.0.0/84.68.10.12/g" )
                # cng_line=$(echo $cng_line | sed "s/0.0.0.0/84.68.10.12/g" )
                add_remediation 81
                modify=1;
                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi
        # echo "rule 79"



        #RULE 80: detection of 'etree.XMLParser(resolve_entities=True)' AND 'XMLParser(resolve_entities=True)' OR 'etree.XMLParser()' AND 'XMLParser()'
        #echo $line | grep -E -q -i "etree.XMLParser\(resolve_entities=True\)|XMLParser\(resolve_entities=True\)|XMLParser\(([^)]+)?\)"
        echo $line | grep -E -q -i "XMLParser\("
        if [ $? -eq 0 ]; then
            #echo "RULE 80"
            echo $line | grep -v -q "[a-zA-Z0-9]XMLParser("
            if [ $? -eq 0 ]; then
                detection=0
                #echo "RULE 80 - lxml.etree.XMLParser"
                #CASO in cui XMLparser appartiene alla libreria lxml.etree
                #RULE 80: detection of 'etree.XMLParser
                echo $line | grep -E -q -i "etree\.XMLParser\("
                if [ $? -eq 0 ]; then    
                    echo $line | grep -v -q "resolve_entities[ ]*=[ ]*False"
                    if [ $? -eq 0 ]; then
                        detection=1
                    fi
                    echo $line | grep -v -q "no_network[ ]*=[ ]*True"
                    if [ $? -eq 0 ]; then
                        detection=1
                    fi                    
                    echo $line | grep -v -q "dtd_validation[ ]*=[ ]*True"
                    if [ $? -eq 0 ]; then
                        detection=1
                    fi  

                    if [ $detection -eq 1 ]; then
                        add_remediation 140
                    fi
                else
                    detection=1
                    add_remediation 62
                    add_remediation 141    
                fi
                if [ $detection -eq 1 ]; then
                    modify=1;
                    if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1
                    fi
                fi
            fi

        fi
        # echo "rule 80"



        #RULE 81: detection of 'etree.XSLTAccessControl(read_network=True...)' AND 'XSLTAccessControl(read_network=True...)'
        echo $line | grep -E -q -i "etree.XSLTAccessControl\(.*read_network=True|XSLTAccessControl\(.*read_network=True|XSLTAccessControl\(.*write_network=True"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]XSLTAccessControl(.*read_network=True"
            if [ $? -eq 0 ]; then
                code_before=$(echo $line | awk -F 'XSLTAccessControl\\(' '{print $1}')
                parameters=$(echo $line | awk -F 'XSLTAccessControl\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                #rem_line=$(echo $rem_line | sed "s/$code_before"XSLTAccessControl"($parameters/parser = etree.XMLParser(resolve_entities=False/g" | sed "s/$code_before"XSLTAccessControl"( $parameters/parser = etree.XMLParser(resolve_entities=False/g" )
                #cng_line=$(echo $cng_line | sed "s/$code_before"XSLTAccessControl"($parameters/PARSER = ETREE.XMLPARSER(RESOLVE_ENTITIES=FALSE/g" | sed "s/$code_before"XSLTAccessControl"( $parameters/PARSER = ETREE.XMLPARSER(RESOLVE_ENTITIES=FALSE/g" )
                #echo $line | grep -E -q -i "access_control"
                #if [ $? -eq 0 ]; then
                #    name_var=$(echo $line | awk -F 'access_control' '{print $2}'| awk -F  '\\)' '{print $1}')
                #    first_char=${name_var::1}
                #    if [ $first_char == "=" ]; then
                #        name_var="${name_var:1}"
                #    fi
                #fi
                #rem_line=$(echo $rem_line | sed "s/XMLParser(resolve_entities=False)/XMLParser(resolve_entities=False) \\\n $name_var = etree.XSLTAccessControl.DENY_ALL/g" | sed "s/XMLParser(resolve_entities=False )/XMLParser(resolve_entities=False) \\\n $name_var = etree.XSLTAccessControl.DENY_ALL/g" )
                #cng_line=$(echo $cng_line | sed "s/XMLParser(resolve_entities=False)/XMLPARSER(RESOLVE_ENTITIES=FALSE) \\\n $name_var = ETREE.XSLTACCESSCONTROL.DENY_ALL/g" | sed "s/XMLParser(resolve_entities=False )/XMLPARSER(RESOLVE_ENTITIES=FALSE) \\\n $name_var = ETREE.XSLTACCESSCONTROL.DENY_ALL/g" )
                add_remediation 126
                modify=1;
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi
        # echo "rule 81"



        #RULE 82: detection of 'os.chmod(file.bin)'
        echo $line | grep -E -q -i "os.chmod\([^a-z]*[a-z]*\.bin"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]os.chmod([^a-z]*[a-z]*\.bin"
            if [ $? -eq 0 ]; then
                #rem_line=$(echo $rem_line | sed "s/.bin/.txt/g" )
                #cng_line=$(echo $cng_line | sed "s/.bin/.TXT/g" )
                modify=2;
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi
        # echo "rule 82"


        #RULE 83: detection of INCREMENT
        echo $line | grep -q -i "while [^<]*<"
        if [ $? -eq 0 ]; then
            var=$(echo $line | awk -F "while" '{print $2}' | awk -F ":" '{print $1}'| awk -F "<" '{print $1}'| awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "<" ]; then
                    var=$(echo $line | awk -F "while" '{print $1}' | awk '{print $(NF-1)}')                    
                fi 
                fin_param=$(echo $line | awk -F "while" '{print $2}' |   awk -F "<" '{print $2}'| awk -F ":" '{print $1}' | awk '{print $NF}')
                
                ####	CHECK
                echo $line | grep -E -v -q "$var\+\+|$var \+\+|$var\+=1|$var=$var\+1|$var = $var \+ 1|$var= $var \+ 1|$var=$var \+ 1|$var=$var\+ 1|$var =$var \+ 1|$var =$var\+ 1"
                if [ $? -eq 0 ]; then
                    #rem_line=$(echo $rem_line | sed "s/while $var<n:/while $var<n: \\\n $var++/g" )
                    #cng_line=$(echo $cng_line | sed "s/while $var<n:/WHILE $var<N: \\\n $var++/g" )
                    add_remediation 127
                    modify=1;
                    if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Security Logging and Monitoring Failures"
                        let sec_log=sec_log+1
                    fi
                fi
            fi  
        fi
        # echo "rule 83"



        #RULE 84: detection of lock
        #echo $line | grep -E -q -i "= Lock\(\).*\.acquire\(\)|=Lock\(\).*\.acquire\(\)"
        echo $line | grep -E -q -i "= *(threading\.)?Lock\(\).*\.acquire\(\)"
        if [ $? -eq 0 ]; then
            echo "RULE 84"
            var=$(echo $line | awk -F "Lock\\\(" '{print $1}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "Lock\\\(" '{print $1}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 
                
                ####	CHECK
                echo $line | grep -v -q "if $var.locked()"
                if [ $? -eq 0 ]; then
                    # rem_line=$(echo $rem_line | sed "s/$var = Lock().*$var.acquire()/lock = Lock() \\\n if $var.locked(): \\\n $var.acquire()/g" )
                    # cng_line=$(echo $cng_line | sed "s/$var = Lock().*$var.acquire()/LOCK = LOCK() \\\n IF $var.LOCKED(): \\\n $var.ACQUIRE()/g" )
                    add_remediation 84
                    modify=1;
                    if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Security Logging and Monitoring Failures"
                        let sec_log=sec_log+1
                    fi
                fi
            fi
        fi
        # echo "rule 84"



        #RULE 85: detection of with open ... as value: ... value.read()
        num_occ=$(echo $line | awk -F "with open\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        det_var=0;
        while [ $i -le $num_occ ]; do
            let det_var=i+1;
            var=$(echo $line | awk -F "with open\\\(" -v i="$det_var" '{print $i}' | awk -F "," '{print $1}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else 
                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g"  | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" |  sed "s/'$var'/ /g"  | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g")
                echo $line | grep -q -i "with open(.*as.*\.read("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if os.path.isfile\($var\)|if os.path.isfile\( $var \)|if os.path.isfile\( $var\)|if os.path.isfile\($var \)"
                    if [ $? -eq 0 ]; then
                        add_remediation 96
                        add_remediation 97
                        modify=1; # --> remediated later 
                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Broken Access Control"
                            let bac=bac+1
                        fi
                    fi
                fi

            fi
            let i=i+1;
            let check=num_occ+1;
        done
        # echo "rule 85"


        #RULE 86: detection of DSA use whith library cryptography.hazmat
        echo $line |  grep -E -i -q "dsa\.generate_private_key\(|dsa.generate_parameters\(|dsa\.DSAParameterNumbers\(|dsa\.DSAPublicNumbers\(|dsa\.DSAPrivateNumbers\("
        if [ $? -eq 0 ]; then
            echo $line |  grep -E -v -q "dsa\.generate_parameters\(|dsa\.DSAParameterNumbers\(|dsa\.DSAPublicNumbers\(|dsa\.DSAPrivateNumbers\("
            if [ $? -eq 0 ]; then
                add_remediation 137
                add_remediation 138
            fi         
            add_remediation 139
            #value=$(echo $line | awk -F 'DSA.generate\\(' '{print $2}' | awk -F  ')' '{print $1}')
            # rem_line=$(echo $rem_line | sed "s/DSA.generate($value/DSA.generate(2048/g" | sed "s/DSA.generate( $value/DSA.generate(2048/g")
            # cng_line=$(echo $cng_line | sed "s/DSA.generate($value/DSA.GENERATE(2048/g" | sed "s/DSA.generate( $value/DSA.GENERATE(2048/g")

            modify=1;
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi
        # echo "rule 85"

##################################################sql 8F CLUSTER 6
        rule8="(\"SELECT|\"DELETE|\"UPDATE|\"INSERT).*\" *% *\(?(flask\.)?request.*\.get\(.*\)\)?"
        rule9="(\"SELECT|\"DELETE|\"UPDATE|\"INSERT).*\" *.format\((flask\.)?request.*\.get\(.*\)\)"
        rule10="('SELECT|'DELETE|'UPDATE|'INSERT).*{(flask\.)?request.*\.get\(.*\)}'" # snippet linea 7, non funziona
        # negli snippet originali la source è una variabile request passata in input dall'utente
        # qui semplicemente verifico se c'è una chiamata a una funzione SQL senza i prepared statements
        #ma non verifico che la variabile sia user controlled --> potrebbe sicuramente causare falsi positivi
        rule11="(order_by|filter|like|group_by|join|like|distinct|extra)\(.*\.format\(.*\)\).*" # esempio: query = query.order_by("string{}".format(var))
        rule12="(order_by|filter|like|group_by|join|like|distinct|extra)\(.*%.*\).*" # esempio: query = query.order_by("string{}".format(var))
        regex="($rule8|$rule9|$rule10|$rule11|$rule12)"
        if echo "$new_line" | grep -q -E "$regex"; then
            add_remediation 94
            add_remediation 95
            modify=1; #NOT MOD
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi
        # echo "rule 8F"

        ######################## RULE 18F - CLUSTER 12 ENVIRONMENT pattern: Environment() or Environment(autoescape=False)
        echo "$line" | grep -q "Environment("
        # Controlla il risultato di grep
        if [ $? -eq 0 ]; then
            # Se la riga contiene "Environment()", verifica che non contenga "autoescape=True" o "autoescape=select_autoescape"
            echo "$line" | grep -E -q -v "autoescape *= *True|autoescape *= *select_autoescape"            
            # Controlla il risultato di grep -v
            if [ $? -eq 0 ]; then
                add_remediation 90
                add_remediation 91
                modify=1;
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi
        # echo "rule 18F"


        #final timestamp all rules for snippet
        end_snippet=$(date +%s.%N)   
        if [ $name_os = "Darwin" ]; then  #MAC-OS system
            runtime_snippet=$( echo "$end_snippet - $start_snippet" | bc -l )
        elif [ $name_os = "Linux" ]; then #LINUX system 
            runtime_snippet=$(python3 -c "print(${end_snippet} - ${start_snippet})")
        fi


        ##################          ADJUSTING DATA         #######################
        line=$(echo "$line" | sed "s/PRODUCT_SYMBOL/*/g")
        #rem_line=$(echo $rem_line | sed "s/PRODUCT_SYMBOL/*/g")
        #cng_line=$(echo $cng_line | sed "s/PRODUCT_SYMBOL/*/g")



        ##################          FINAL CHECK         #######################
        if [[ ! $vuln ]]; then
            let dimtestset=dimtestset+1;
            echo "SAFE-CODE" >> $outputFile;
            echo "caso SAFE-CODE"
        else
            echo "caso VULNERABLE-CODE: $vuln , $modify"
            ############################## NEW REMEDIATION 2
            already_rem=0
            # Itera attraverso gli array di patterns e replacements
            tmp_line="$line"
            tmp_line_cng="$line"
            injected_var_index=0
            for i in "${remdiationToExecute[@]}"; do #use only the remediation that are needed
                pattern="${patterns[$i]}"
                replacement="${replacements[$i]}"
                pattern_not="${patterns_not[$i]}"
                source="${sources[$i]}"
                injected_var="${injected_vars[$injected_var_index]}"
                #selezione del commento del commento
                import="${imports[$i]}"
                comment="${comments[$i]}"


                ((injected_var_index++))
                #echo "La variabile iniettata è: ${injected_var[$injected_var_index]}"
                # Verifica se la linea contiene il pattern corrente
                

                ## new check for injected var
                if [[ "$pattern" == *"INJECTED_VAR"* ]]; then
                    pattern=$(echo "$pattern" | sed -E "s#INJECTED_VAR#$injected_var#g")
                fi

                if [[ "$replacement" == *"INJECTED_VAR"* ]]; then
                    replacement=$(echo "$replacement" | sed -E "s#INJECTED_VAR#$injected_var#g")
                fi

                if [[ "$pattern_not" == *"INJECTED_VAR"* ]]; then
                    pattern_not=$(echo "$pattern_not" | sed -E "s#INJECTED_VAR#$injected_var#g")
                fi
                #echo "pattern provato: $pattern"
                #echo "injected_var: $injected_var"
                #echo "temp line $tmp_line"
                #if [[ "$tmp_line" =~ $pattern ]]; then

                addComment=false
                #controlla se il pattern è uguale a NO-REMEDIATION-PATTERN"
                if [[ "$pattern" == *"NO-REMEDIATION-PATTERN"* ]]; then
                    addComment=true
                fi

                echo "pattern testato: $pattern"
                if echo "$tmp_line" | grep -qE "$pattern"; then
                    echo "pattern applicato: $pattern con id $i"
                    echo "replacement applicato: $replacement"
                    addComment=true

                    captured_function=""
                    captured_argument=""
                    captured_var=""
                    #echo "linea: $tmp_line"
                    # Applica la remediation
                    if [[ "$tmp_line" =~ $pattern ]]; then
                        captured_function="${BASH_REMATCH[1]}" # prendo il nome della funzione, es: cursor.engine() --> cursor
                        #echo "captured_function: $captured_function"
                        captured_argument="${BASH_REMATCH[2]}" # prendo argomento della funzione, es:  cursor.engine(ARG) --> ARG
                        #captured_var=""

                    fi
                    echo "source: $source"
                    if [[ "$line" =~ $source ]]; then
                        captured_var="${BASH_REMATCH[1]}"
                        echo "captured_var: $captured_var"
                    fi
                    #echo "sto per rimediare: $modify"
                    if [ $modify -eq 0 ] || [ $modify -eq 1 ]; then 
                        #echo "$tmp_line"
                        result=""
                        result=$(remediate_line "$tmp_line" "$pattern" "$replacement" "$captured_function" "$captured_argument" "$captured_var" "$pattern_not" "$tmp_line_cng" )
                        echo "result: $result"
                        echo "NUOVO"
                        echo "NUOVO"
                        tmp_line="$(echo "$result" | awk -F "CNG_LINE" '{print $1}' )"
                        tmp_line_cng="$(echo "$result" | awk -F "CNG_LINE" '{print $2}' )"
                        
                        modify=1
                        already_rem=1
                    fi


                fi
                #controlla se addComment è true e in tal caso aggiunge il commento e l'import
                if [ "$addComment" = true ]; then
                    #aggiunta del commento
                    exists=false

                    # Controlla se il commento è già presente in selectedComments
                    for selected in "${selectedComments[@]}"; do
                        if [[ "$selected" == "$comment" ]]; then
                            exists=true
                            break
                        fi
                    done

                    importExists=false
                    for selectedImport in "${selectedImports[@]}"; do
                        if [[ "$selectedImport" == "$import" ]]; then
                            importExists=true
                            break
                        fi
                    done

                    # Se il commento non è stato ancora aggiunto, lo aggiunge a selectedComments
                    if [[ "$exists" == false ]]; then
                        selectedComments+=("$comment")
                    fi

                    # Se l'import non è stato ancora aggiunto, lo aggiunge a selectedImports
                    if [[ "$importExists" == false ]]; then
                        selectedImports+=("$import")
                    fi
                    addComment=false
                fi
            done ###################### NEW REMEDIATION 2

            if [ $modify -eq 1 ] && [ $already_rem -eq 0 ]; then #vuln AND rem
                #echo "$cng_line"
                echo "caso 1"
                #{ echo $vuln; echo "NO-REM"; echo $tmp_line; } | tr "\n" " " >> $outputFile;
                echo "$vuln" >> $outputFile;
                echo "REM-WITH-COMMENT" >> $outputFile;
                echo "$tmp_line" >> $outputFile;
                
                # Cicla su ogni commento e salvalo nel file
                for selected in "${selectedComments[@]}"; do
                    echo "$selected" >> "$outputFile"
                done

                let countvuln=countvuln+1;
                let dimtestset=dimtestset+1;
                let contMod=contMod+1;
            elif [ $modify -eq 1 ] && [ $already_rem -eq 1 ]; then
                echo "caso 2"
                #echo "$line" 
                echo "$vuln" >> $outputFile;
                echo "$line" >> $outputFile;
                echo "$tmp_line" >> $outputFile;

                # Cicla su ogni commento e salvalo nel file
                for selected in "${selectedComments[@]}"; do
                    echo "$selected" >> "$outputFile"
                done

                echo "imports" >> "$outputFile"
                for selectedImport in "${selectedImports[@]}"; do
                    echo "$selectedImport" >> "$outputFile"
                done

                #{ echo $vuln; echo "$tmp_line"; } | tr "\n" " " >> $outputFile;
                let countvuln=countvuln+1;
                let dimtestset=dimtestset+1;
                let contMod=contMod+1;
            elif [ $modify -eq 2 ]; then #vuln BUT NOT rem
                echo "caso 3"
                #{ echo $vuln; echo "NO-REM"; echo $tmp_line; } | tr "\n" " " >> $outputFile;
                echo "$vuln" >> $outputFile;
                echo "NO-REM" >> $outputFile;
                echo "$tmp_line" >> $outputFile;

                let countvuln=countvuln+1;
                let dimtestset=dimtestset+1;
                let contNoMod=contNoMod+1;
            fi
        fi



        ##################          FINAL COUNT VULNERABILITIES         #######################
        # For each line, if a category was toggled, increment the global counter for that category
        if [ $inj -gt 0 ]; then
            ((inj_count++))
        fi
        if [ $crypto -gt 0 ]; then
            ((crypto_count++))
        fi
        if [ $sec_mis -gt 0 ]; then
            ((sec_mis_count++))
        fi
        if [ $bac -gt 0 ]; then
            ((bac_count++))
        fi
        if [ $id_auth -gt 0 ]; then
            ((id_auth_count++))
        fi
        if [ $sec_log -gt 0 ]; then
            ((sec_log_count++))
        fi
        if [ $ins_des -gt 0 ]; then
            ((ins_des_count++))
        fi
        if [ $ssrf -gt 0 ]; then
            ((ssrf_count++))
        fi
        if [ $soft_data -gt 0 ]; then
            ((soft_data_count++))
        fi

    fi

done < "$input"

##################          RULES COMPUTATIONAL TIME         ########################### 
end=$(date +%s.%N)   
if [ $name_os = "Darwin" ]; then  #MAC-OS system
    runtime=$( echo "$end - $start" | bc -l )
elif [ $name_os = "Linux" ]; then #LINUX system 
    runtime=$(python3 -c "print(${end} - ${start})")
    echo "runtime=$runtime"
fi


##################          RESULTS ON FILE         ########################### 
#DET file
