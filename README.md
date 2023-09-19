# Log.py

**Description**:  
This utility aids in parsing logs to extract and display various types of information. It supports automatic pattern detection, specific line and column extraction, regular expression search, and more.

## Features:

1. **Auto Pattern Detection**: Automatically search for common patterns such as IPs, timestamps, dates, directories, and more.
2. **Custom Search**: Use a string or regular expression to highlight matching strings.
3. **Column Extraction**: Extract data from specific columns or ranges of columns from the log.
4. **Row Selection**: Display specific rows or ranges of rows.
5. **Important Note**: Most options display data occurrences only once, along with the number of occurrences found. 

## Usage:

```
python log.py <filename> [options]
```

### Recommendation:
Configure an alias in zsh.
```
nano ~/.zshrc 
```

\# A Log.py alias

alias logpy='/path/to/log.py'

```
source ~/.zshrc
```

### Options:

#### Postitional Argument:
- \<filename\> The log file to parse.
#### Help:
- **-h, --help**: Display options and get help. 
#### Automatic & Individual Analysis:
- **-a, --auto**: Automatic pattern detection and analysis.
- **-d, --date**: Search for dates.
- **-D, --directory**: Search for directories.
- **-e, --email**: Search for emails.
- **-H, --hash**: Search for hashes.
- **-i, --ip**: Search for IP addresses.
- **-I, --uuid**: Search for UUIDs.
- **-m, --method**: Search for HTTP methods.
- **-t, --timestamp**: Search for timestamps.
- **-u, --url**: Search for URLs.
- **-U, --user**: Search for User Agents.
- **-s, --status**: Search for Status codes.
#### Individual Search:
- **-g, --grep <pattern>**: Highlight lines matching the provided string or regular expression pattern.
#### Column and Row Processing:
- **-C, --column [num]**: List by specified column number(s). Examples: `-C 2`, `-C 1-4`
- **-R, --row [num]**: List by line number, line number range, or multiple line numbers. Default is all rows. Examples: `-R` (all rows), `-R 123-321`, `-R 4 10 21`.
- **-S, --separator <separator>**: Specify a custom separator for columns. Default is space.
- **-X, --highlight**: Highlight specific column in rows.
- **-A, --mathematical_addition**: Perform addition on specified column and display results.
#### Processing with Additional Files:
- **-f, --input_file <file>**: Search for patterns based on a provided input file.
- **-o, --out_file <file>**: Write results to a specified output file.
- **-c, --concatenate**: Concatenate results when writing to an output file.



## Examples:

**Display entire log**:  
```
python log.py <filename>
```

**Search for specific pattern**:  
```
python log.py <filename> -g 'Google'
```

**List data from  columns 2 to 5 for rows 10 to 15**:  
```
python log.py <filename> -C 2-5 -R 10-15
```
**List data from  rows 5 to 20 and highlight column 4**:  
```
python log.py <filename> -R 5-20 -X 4
```
**Output results to a file**:  
```
python log.py <filename> -g "ERROR" -o output.txt
```

## Errors and Exceptions:

- If a specified file is not found, an error is displayed.
- If an invalid regex pattern is provided, an error is displayed.

## Dependencies:

This script use's standard Python libraries.
