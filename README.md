# Log Analysis Script

## Description
This Python script analyzes server log files to extract and analyze key information, such as:
1. **Requests per IP Address**: Counts requests made by each IP and sorts results.
2. **Most Frequently Accessed Endpoint**: Identifies the endpoint with the highest number of accesses.
3. **Suspicious Activity Detection**: Flags IPs with more than 10 failed login attempts.
4. **Output Results**: Displays results in the terminal and saves them to a CSV file.

The script follows Object-Oriented Programming (OOP) principles for modularity and extendibility.

---

## Features
### Key Features
- **Efficient Data Handling**:
  - Uses `Counter` and `defaultdict` for fast data aggregation.

- **OOP Design**:
  - Clear separation of tasks into reusable methods for better maintainability.
  - Easy to extend for additional log analysis features.

- **Flexible Input/Output**:
  - Accepts log file paths as runtime arguments.
  - Automatically generates a CSV file name based on the log file or accepts a custom name.

- **Clear Output**:
  - Results are displayed in the terminal and saved in an organized CSV format.

- **Memory Optimization**:
  - Processes logs line by line to handle large files.

---

## Usage

### Prerequisites
- Python 3.6 or higher

### Installation
1. Clone the repository or download the script.
2. Ensure Python is installed on your system.

### Running the Script
Run the script from the terminal:

```bash
python .\log_processor.py <path_to_log_file>
```

### Optional Argument: 
- Use -o or --output to specify a custom name for the CSV output file.
- If no output file is specified, a default name is generated in the format: log_analysis_results_<log_file_name>.csv.

```bash
python .\log_processor.py <path_to_log_file> -o custom_output.csv
```
