#!/usr/bin/env python3
# Author: ezesec

import argparse
import re
import os
import sys
import datetime
import traceback
from collections import defaultdict
from typing import List, Union

# Class to store ANSI escape sequences for text formatting
class Text:
    greenBold = '\033[1m\033[32m'
    purpleBold = '\033[1m\033[35m'
    redBold = '\033[1m\033[31m'
    darkGrayBg = '\033[48;5;232m'
    green = '\033[32m'
    blue = '\033[34m'
    orange = '\033[33m'
    red = '\033[31m'
    end = '\033[0m'

# Welcome message
def welcome():
    logo = f"""{Text.orange}
 ___      _______  _______        _______  __   __ 
|   |    |       ||       |      |       ||  | |  |
|   |    |   _   ||    ___|      |    _  ||  |_|  |
|   |    |  | |  ||   | __       |   |_| ||       |
|   |___ |  |_|  ||   ||  | ___  |    ___||_     _|
|       ||       ||   |_| ||   | |   |      |   |  
|_______||_______||_______||___| |___|      |___|  
###################################################

{Text.end}A python script to analyze log files.  Use -h for help.
"""
    print(logo)

# Argument parser
def parse_args():
    parser = argparse.ArgumentParser(description='A python script to analyze log files.')
    parser.add_argument('file', help='The log file to analyze.')
    parser.add_argument('-a', '--auto', action='store_true', help='Automatically analyze the log file.')
    parser.add_argument('-d', '--date', action='store_true', help='Search for dates.', dest='date_flag')
    parser.add_argument('-D', '--directory', action='store_true', help='Directory of wordlist files.', dest='directory_flag')
    parser.add_argument('-e', '--email', action='store_true', help='Search for email addresses.', dest='email_flag')
    parser.add_argument('-H', '--hash', action='store_true', help='Search for hashes.', dest='hash_flag')
    parser.add_argument('-i', '--ip', action='store_true', help='Search for IP addresses.', dest='ip_flag')
    parser.add_argument('-I', '--uuid', action='store_true', help='Search for UUIDs.', dest='uuid_flag')
    parser.add_argument('-m', '--method', action='store_true', help='Search for request methods.', dest='method_flag')
    parser.add_argument('-t', '--timestamp', action='store_true', help='Search for timestamps.', dest='timestamp_flag')
    parser.add_argument('-u', '--url', action='store_true', help='Search for URLs.', dest='url_flag')
    parser.add_argument('-U', '--user', action='store_true', help='Search for user agents.', dest='user_flag')
    parser.add_argument('-s', '--status', action='store_true', help='Search for status codes.', dest='status_flag')
    search_group = parser.add_argument_group('Search Options', 'Arguments related to searching.')
    search_group.add_argument('-g', '--grep', type=str, metavar='[string]',help='Search for grepable strings.')
    list_group = parser.add_argument_group('Column and Row Processing', 'Arguments related to column and row processing.')
    list_group.add_argument('-C', '--column', type=str, metavar='[num]', help='List by column number or column number range. Example: -C 1 or -C 1-3.')
    list_group.add_argument('-R', '--row', type=str, metavar='[num]', nargs='*', default=[], help='List by line number, line number range, or multiple line numbers. Default: All rows. Example: -R or -R 123-321 or -R 4 10 21.')
    list_group.add_argument('-S', '--separator', type=str, metavar='separator',nargs='?', const=" ", default=None, help='List column separator. Default: -S \' \'.')
    list_group.add_argument('-X', '--highlight', type=int, metavar='[num]', help='Highlight a column number.')
    list_group.add_argument('-A', '--mathematical_addition', help='The sum of all integers found in a column.', default=None, action='store_true')
    file_group = parser.add_argument_group('Processing with Additional Files.', 'Arguments related to input, output files.')
    file_group.add_argument('-f', '--input_file', type=str, metavar='[input_file]', default=None, help='Search with a wordlist file.')
    file_group.add_argument('-o', '--out_file', type=str, metavar='[output_file]',default=None, help='Output the results to a file.')
    file_group.add_argument('-c', '--concatenate', action='store_true', default=None, help='Concatenate the results of the output file.')
    args = parser.parse_args()
    return args

PATTERNS = {
    # IPv4 Addresses: Matches patterns like '192.168.1.1'
    # IPv6 Addresses: Matches patterns like '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    'ip': (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\s*(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b', 'IP Addresses'),

    # Request Methods: Matches HTTP methods like 'GET', 'POST', etc.
    'method': (r'\b(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)\b', 'Request Methods'),

    # Status Codes: Matches HTTP status codes like '404', '200', etc.
    'status': (r'\b(200|301|302|304|400|401|403|404|405|500|501|502|503|504|505)\b', 'Status Codes'),

    # URLs: Matches patterns like 'https://www.example.com'
    'url': (r'https?://(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,6}(?:/[^)\s:;"\']*)?', 'URLs'),
   
    # Directories: Matches patterns like '/user/profile'
    'directory': (r'\/(?!\b(?i:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\b)[\w-]+(?=.*[a-zA-Z])\/[\w-]+', 'Directories'),
    
    # Timestamps: Matches patterns like '12/Dec/1991:12:34:56' and epoch time (e.g., 1596677464)
    'timestamp': (r'\d{1,2}/[a-zA-Z]{3}/\d{4}:\d{2}:\d{2}:\d{2}|\b\d{10}\b', 'Timestamps'),

    # Dates in "12/Dec/1991" or "12-DEC-1991" formats and YYYY-MM-DD, DD-MM-YYYY, MM-DD-YYYY
    'date': (r'\b\d{1,2}/[a-zA-Z]{3}/\d{4}|\d{1,2}-[A-Z]{3}-\d{4}\b|\b\d{1,2}/\w{3}/\d{4}\b|\b\d{4}-\d{2}-\d{2}\b|\b\d{2}-\d{2}-\d{4}\b|\b\d{2}-\d{1,2}-\d{4}\b', 'Dates'),

    # Email Addresses: Matches patterns like 'example@email.com'
    'email': (r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', 'Email Addresses'),

    # Hashes:
    # - MD5: 32 hexadecimal characters
    # - SHA-1: 40 hexadecimal characters
    # - SHA-256: 64 hexadecimal characters
    # - SHA-512: 128 hexadecimal characters
    'hash': (r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{128}\b', 'Hashes'),

    # UUIDs: Matches patterns like 'f47ac10b-58cc-4372-a567-0e02b2c3d479'
    'uuid': (r'\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-\b[a-fA-F0-9]{12}\b', 'UUIDs'),

    # User Agents: Matches patterns like Linux x86_64 or Windows NT 10.0 or Mac OS X.  Used only to identify possible user agents.
    'user': (r'\b((Mac OS X|Linux|Windows)\s(\w*)(\s\d+\.\d+)?)\b', 'User Agents')
}

def display_log(file):
    """This function displays the entire content of a given log file, line by line."""
    # Open the file in read mode
    with open(file, 'r') as f:
        # Enumerate through each line, printing with the line number
        for idx, line in enumerate(f, start=1):
            print(f'{Text.greenBold}Line {idx}:{Text.end} {line}', end='')


def highlight_matches(file, pattern):
    """
    This function searches for a specified pattern within a file and highlights the matched content.
    If the pattern is a regular expression, it compiles the regex and uses it to search through the file.
    """
    output = []
    total_matches = 0

    # Try to compile the pattern as regex
    try:
        compiled_pattern = re.compile(pattern)
    except re.error as e:
        # Exit with an error message if the pattern is an invalid regex
        output.append(f'{Text.red}Error: Invalid regex pattern. {e}{Text.end}')
        sys.exit(1)

    search_results = []

    # Open the file and search line by line
    with open(file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            if compiled_pattern.search(line):
                line = line.rstrip()  # Strip the newline character from the end of the line
                # If the line contains the pattern, add it to the search results
                search_results.append(line)
                total_matches += 1
                matched_string = compiled_pattern.search(line).group()
                output.append(f'{Text.blue}Line {line_num}{Text.end}: {line.replace(matched_string, f"{Text.purpleBold}{matched_string}{Text.end}")}')

    
    # Add the total match count to the output
    output.append(f'{Text.greenBold}TOTAL: {total_matches}{Text.end}\n')

    # If no matches found, print an error message
    if not search_results:
        print(f'{Text.redBold}Error: Pattern not found.{Text.end}')
        sys.exit(1)
    else:
        return output


def list_columns(file, column, separator, addition, rows=None):
    """Function that displays specific columns from a given file"""
    # Initializations
    counts = defaultdict(int)
    sum_col = 0  # To keep track of the summation (if addition is True)
    error_col = 0
    error_lines = []
    unique_matches = set()
    total_matches = 0
    specific_rows = set()
    output = []

    # Set default separator if not provided
    if separator is None:
        separator = ' '

    # If 'all' is passed in rows, consider all rows
    if rows == ['all']:
        rows = None

    # Extract specific rows to process if any are given
    if rows:
        for item in rows:
            if '-' in item:
                start, end = map(int, item.split('-'))
                specific_rows.update(range(start, end + 1))
            else:
                specific_rows.add(int(item))

    # Handle column range, e.g., "2-4" or a single column
    if '-' in str(column):
        start_col, end_col = map(int, column.split('-'))
        col_range = range(start_col, end_col + 1)
    else:
        col_range = [int(column)]

    try:
        with open(file, 'r') as f:
                for line_number, line in enumerate(f, start=1):
                    
                    # If specific rows are mentioned, process only those
                    if specific_rows and line_number not in specific_rows:
                        continue
            
                    columns = line.strip().split(separator)

                    try:
                        # Combine data from specified columns
                        combined_col_data = separator.join(columns[col - 1] for col in col_range)
                    except IndexError:
                        print(f'Error on line {line_number}: {line}')

                    # If the addition flag is set, try to sum up the data
                    if addition:
                        try:
                            if '-' in str(column):
                                current_value = sum(int(columns[col - 1]) for col in col_range)
                            else:
                                current_value = int(combined_col_data)
                            sum_col = sum_col + current_value
                            output.append(f'{Text.blue}Line {line_number}:{Text.end} {sum_col - current_value} + {current_value} = {sum_col}')
                        except ValueError:
                            output.append(f'{Text.blue}Line {line_number}:{Text.red} Error: Data in the specified column(s) is not an integer.{Text.end}')
                            error_col += 1
                            error_lines.append(line_number)
                    else:
                        # If not in addition mode, just count occurrences
                        counts[combined_col_data] += 1
                        unique_matches.add(combined_col_data)
                        total_matches += 1 
    
    except Exception as e:
        output.append(f'{Text.red}Error: {e}{Text.end}')
        sys.exit(1)

    # Prepare output based on the mode (addition or occurrence count)
    if addition:
        output.append(f'\n{Text.greenBold}Sum of Column(s) {column}: {sum_col}{Text.end}')
        output.append(f'{Text.redBold}Errors: {error_col}{Text.end}\n')
        output.append(f'{Text.redBold}Lines with errors: {Text.end} {" ".join(map(str, error_lines))}\n')
    else:
        output.append(f'{Text.greenBold}Column(s): {column}{Text.end}')
        for key, value in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            output.append(f'{key} {Text.purpleBold}{value}{Text.end}')
        output.append(f"\n{Text.blue}#TOTAL: {total_matches}{Text.end}")
        output.append(f'{Text.orange}UNIQUE: {len(unique_matches)}{Text.end}\n')
        
    return output


def list_rows(file: str, lines: Union[int, str, List[str]] = 'all', separator: str = None, highlight_col: int = None):
    """Function that reads specific lines or range of lines from a given file"""

    # Utility function to highlight certain parts of text
    def highlight(text, char, highlight_col): 
        # Highlight the specified column using the provided separator or defaulting to space
        if highlight_col is not None:
            parts = text.split(separator or ' ')
            if 0 <= highlight_col -1 < len(parts):
                parts[highlight_col -1] = f'{Text.purpleBold}{parts[highlight_col -1]}{Text.end}'
            text = (separator or ' ').join(parts)

        # Highlighting of separators in the text
        if char is None:
            char = " "
            highlighted_text = re.sub(r' (?!\n)', f'{Text.darkGrayBg} {Text.end}', text)
        else:
            highlighted_text = text.replace(char, f'{Text.darkGrayBg}{char}{Text.end}')

        return highlighted_text

    # Utility function to display progress in percentage
    def display_progress(current, total):
        percentage_displayed = current / total * 100
        print(f'\n{Text.purpleBold}[{percentage_displayed:.2f}% of {total} lines]{Text.end}')

    # Get terminal dimensions to support pagination
    rows, columns = os.popen('stty size', 'r').read().split()
    rows = int(rows) - 2  # Two rows reserved for progress and user input

    try:
        with open(file, 'r') as f:
            all_lines = f.readlines()
            total_lines = len(all_lines)

            specific_lines = []  # Captures desired lines or ranges
            
            # Check if lines parameter is a list or a single entry
            if isinstance(lines, list):
                if 'all' in lines:
                    specific_lines = list(range(total_lines))
                else:
                    # Capture line ranges (like 1-4) and single line numbers
                    for item in lines:
                        if '-' in item:
                            start, end = map(int, item.split('-'))
                            specific_lines.extend(range(start - 1, end))
                        else:
                            specific_lines.append(int(item) - 1)
            else:
                specific_lines.append(int(lines) - 1)

            line_count = 0
            for idx in specific_lines:
                line = all_lines[idx]
                line_count += 1

                # If current page is full, ask the user to continue or quit
                if line_count > rows:
                    display_progress(idx - specific_lines[0], len(specific_lines))
                    choice = input(f"{Text.green}Press Enter to continue or 'q' to quit: {Text.end}")
                    if choice.lower() == 'q':
                        return
                    line_count = 1

                # Highlight and print each line
                print(f'{Text.blue}Line {idx + 1}:{Text.end} {highlight(line.strip(), separator, highlight_col)}')

            # Show final progress
            display_progress(len(specific_lines), len(specific_lines))

    # Handle potential errors in reading or processing the file
    except Exception as e:
        print(f'{Text.red}Error: {e}{Text.end}')
        sys.exit(1)


def input_file_search(file, pattern_file):
    """
    Searches for patterns from a pattern_file in a given file.
    
    Args:
    - file (str): Path to the file in which patterns are searched.
    - pattern_file (str): Path to the file containing the search patterns.
    
    Returns:
    - list: A list containing the search results and relevant counts.
    """
    
    # Dictionary to store the count of each pattern found
    counts = defaultdict(int)
    
    # Set to store each pattern found for uniqueness tracking
    unique_matches = set()
    
    # Total number of matches found
    total_matches = 0
    
    # List to store output results
    output = []

    # Read the pattern file and store each pattern in a list
    with open(pattern_file, 'r') as f:
        patterns = [f"{line.strip()}" for line in f]

    # For each pattern, open the file and search for the pattern
    for pattern in patterns:
        with open(file, 'r') as f:
            for line in f:
                if pattern in line:
                    counts[pattern] += 1
                    unique_matches.add(pattern)
                    total_matches += 1

    # Append results to the output list
    output.append(f'{Text.greenBold}Search Results: {Text.end}')
    
    # Sort the patterns by their count in descending order
    counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    
    # Append each pattern and its count to the output
    for key, value in counts:
        output.append(f'{key} {Text.purpleBold}{value}{Text.end}')

    # If no matches were found, return an empty list
    if not counts:
        return []
    else:
        # Append total and unique counts to the output
        output.append(f"\n{Text.blue}#TOTAL: {total_matches}{Text.end}")
        output.append(f'{Text.orange}UNIQUE: {len(unique_matches)}{Text.end}\n')
        return output

         
def search(file, pattern_key):
    """Search function to search for patterns in a given file. """

    def process_ips(ips, ip_type):
        """Process IPs and return a formatted output"""

        output = []
        output.append(f'{Text.greenBold}{ip_type} IP Addresses:{Text.end}')
        sorted_ips = sorted(ips[ip_type].items(), key=lambda x: x[1], reverse=True)
        for key, value in sorted_ips:
            output.append(f'{key}: {Text.purpleBold}{value}{Text.end}')
        
        output.append(f"\n{Text.blue}#TOTAL {ip_type} IP Addresses: {len(ips[ip_type].items())}{Text.end}")
        output.append(f'{Text.orange}UNIQUE {ip_type} IP Addresses: {len(ips[ip_type])}{Text.end}\n')
        return output
    
    def process_counts(counts, description, pattern_key):
        """Process counts and return a formatted output"""

        output = []
        output.append(f'{Text.greenBold}{description}:{Text.end}')
        
        # Sort the counts
        sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        
        # Handle special cases like 'timestamp'
        for key, value in sorted_counts:
            if pattern_key == 'timestamp' and key.isdigit() and len(key) == 10:
                dt = datetime.datetime.fromtimestamp(int(key))
                output.append(f"{dt.strftime('%Y-%m-%d %H:%M:%S')} ({key}) : {Text.purpleBold}{value}{Text.end}")
            else:
                output.append(f"{key} : {Text.purpleBold}{value}{Text.end}")

        return output

    # Get the pattern and its description based on the given pattern_key
    pattern, description = PATTERNS[pattern_key]

    # Compile the pattern for efficient matching
    compiled_pattern = re.compile(pattern)

    # Initialize default dictionaries to track counts and IPs
    counts = defaultdict(int)
    ips = {'Source': defaultdict(int), 'Destination': defaultdict(int)}

    # Sets to track unique matches and to count total matches
    unique_matches = set()
    total_matches = 0
    output = []

    # Open and read the file line by line
    with open(file, 'r') as f:
        for line in f:
            # Find all pattern matches in the line
            matches = compiled_pattern.findall(line)

            # Skip the line if no matches found
            if not matches:
                continue  

            # Special processing if more than one IP address is found in the line
            if pattern_key == 'ip':
                unique_matches.update(matches)
                # The first IP is the source IP
                ips['Source'][matches[0]] += 1
                total_matches += 1

                # If there is a second IP, it is the destination IP
                if len(matches) > 1:
                    ips['Destination'][matches[1]] += 1
                    total_matches += 1

            # Special processing if the pattern is for user_agents
            elif pattern_key == 'user':
                match = compiled_pattern.search(line)
                if match:
                    full_match = match.group(0)
                    unique_matches.add(full_match)
                    counts[full_match] += 1
                    total_matches += 1

            # For all other patterns
            else:
                unique_matches.update(matches)
                for match in matches:
                    counts[match] += 1
                total_matches += len(matches)

    # Post-process and organize the results to produce the final output
    # Specific handling for IP address patterns
    if total_matches == 0:
        return []

    if pattern_key == 'ip':
        # If there are no destination IPs, list only source IPs
        if not ips['Destination']:
            output.extend(process_ips(ips, 'Source'))
        # If there are destination IPs, list both source and destination IPs
        else:
            output.extend(process_ips(ips, 'Source'))
            output.extend(process_ips(ips, 'Destination'))
        # Append total and unique counts for IPs after processing both source and destination
        output.append(f"{Text.blue}#TOTAL IP Addresses: {total_matches}{Text.end}")
        output.append(f'{Text.orange}UNIQUE IP Addresses: {len(unique_matches)}{Text.end}\n')
    # Handle all other patterns
    else:
        output.extend(process_counts(counts, description, pattern_key))
        # Append total and unique counts for the specific description (like 'Dates')
        output.append(f"\n{Text.blue}#TOTAL {description}: {total_matches}{Text.end}")
        output.append(f'{Text.orange}UNIQUE {description}: {len(unique_matches)}{Text.end}\n')


    # Return the organized output if any counts were found, or if the pattern was for IPs
    return output if counts or pattern_key == 'ip' else []


def strip_ansi_escape(text):
    # Define an ANSI escape sequence pattern
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    # Strip ANSI escape sequences from the given text
    return ansi_escape.sub('', text)


def write_to_file(output_file, data, concatenate):
    # Check if the results should be appended or overwritten
    mode = 'a' if concatenate else 'w'
    
    # Write (or append) the data to the output file
    with open(output_file, mode) as f:
        for item in data:
            # Clean up any ANSI escape sequences for a plain-text output
            clean_result = strip_ansi_escape(item)
            f.write(f"{clean_result}\n")
            
    # Notify the user about the results being written
    action = "Concatenated" if concatenate else "Wrote"
    print(f'{Text.greenBold}{action} results to {output_file}{Text.end}')


def main():
    try:
        welcome()

        # Define flags and arguments constants
        FLAGS = ["auto", "date_flag", "directory_flag", "email_flag", "hash_flag", "ip_flag", 
         "uuid_flag", "method_flag", "timestamp_flag", "url_flag", "user_flag", "status_flag"]
        ARGS = ["grep", "column", "row", "separator", "highlight", "mathematical_addition", "input_file", "out_file", "concatenate"]
        args = parse_args()

        # If none of the flags or arguments are specified, display the log file
        if not any(getattr(args, flag) for flag in FLAGS) and not any(getattr(args, arg) is not None for arg in ARGS):
            display_log(args.file)
        else:
            # Mapping between argument keywords and their respective flags
            arg_dict = {'ip' : 'ip_flag',
                        'timestamp' : 'timestamp_flag',
                        'date' : 'date_flag',
                        'directory' : 'directory_flag',
                        'status' : 'status_flag',
                        'method' : 'method_flag',
                        'url' : 'url_flag',
                        'email' : 'email_flag',
                        'hash' : 'hash_flag',
                        'uuid' : 'uuid_flag',
                        'user' : 'user_flag'}
            
            results = []
            found_result = False
            found_userAgent = False

            if args.row == []:
                args.row = ['all']
           
            # If the "auto" flag is set, search for all patterns in PATTERNS
            if args.auto:
                for pattern_key in PATTERNS.keys():
                    current_results = search(args.file, pattern_key)
                    results.extend(current_results)
                    if pattern_key == 'user' and current_results:
                        found_userAgent = True

            # If grep argument is specified, highlight the matching strings
            elif args.grep:
                results.extend(highlight_matches(args.file, args.grep))

            # If an input_file argument is given, search based on the input file patterns
            elif args.input_file:
                results.extend(input_file_search(args.file, args.input_file))

            # If column argument is specified, list the column specified
            elif args.column:
                # If row argument is not specified, set it to 'all' otherwise list column(s) from the rows specified
                results.extend(list_columns(args.file, args.column, args.separator, args.mathematical_addition, rows=args.row))

            # If row argument is specified, list the row(s) specified
            elif args.row:
                list_rows(args.file, args.row, args.separator, args.highlight)
                return
            else:
                # Get the pattern_keys based on which flags are set
                pattern_keys = [key for key, arg in arg_dict.items() if getattr(args, arg)]
                for pattern_key in pattern_keys:
                    current_results = search(args.file, pattern_key)
                    results.extend(current_results)

            # If an out_file is specified, write the results to the file
            if args.out_file:
                # If user agents are found, append a note
                if found_userAgent:
                    note = '#Note:  Possible user agents have been identified.\n\tUse either -g or -c to get more information.'
                    results.append(note)
                write_to_file(args.out_file, results, args.concatenate)
            else:
                # Display results to console
                for result in results:
                    if result:
                        print(result)
                        found_result = True

                # Print note if user agents are found
                if found_userAgent:
                    print(f'{Text.orange}#Note:{Text.end}  Possible user agents have been identified.\n\tUse either -g or -c to get more information.')

                # If no results are found, print an error message and exit
                if not found_result:
                    print(f'{Text.redBold}Error: No results found.{Text.end}')
                    sys.exit(1)
                    
    # Handle exceptions and print relevant error messages
    except FileNotFoundError:
        print(f'{Text.redBold}Error: The file {args.file} was not found.{Text.end}')
        sys.exit(1)
    except Exception as e:
        print(f'{Text.red}Error: {e}{Text.end}')
        traceback.print_exc()  # This will print the full traceback
        sys.exit(1)

# If the script is run directly, call the main function               
if __name__ == '__main__':
    main()
