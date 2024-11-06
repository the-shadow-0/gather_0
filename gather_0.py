import subprocess
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def run_command(command, capture_output=True):
    """Execute a shell command, returning its output or None on failure."""
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=capture_output, check=True)
        return result.stdout.strip() if capture_output else None
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {command}\n{e.stderr}")
        return None

def create_subdomains_file():
    """Run subfinder to create a subdomains file."""
    logging.info("Running subfinder...")
    run_command("subfinder -dL scope.txt -all -recursive -o subdomains.txt")

def filter_alive_subdomains():
    """Filter for alive subdomains using httprobe and save to a file."""
    logging.info("Filtering alive subdomains...")
    run_command("cat subdomains.txt | httprobe | anew subdomains_alive.txt")

def gather_parameters():
    """Gather parameters from alive subdomains using gau."""
    logging.info("Gathering parameters with gau...")
    run_command("cat subdomains_alive.txt | gau > params.txt")

def filter_parameters():
    """Filter parameters using uro to remove duplicates."""
    logging.info("Filtering parameters with uro...")
    run_command("cat params.txt | uro -o filterparam.txt")

def categorize_files():
    """Separate JavaScript and JSON files from filtered parameters."""
    logging.info("Extracting JavaScript and JSON files...")
    run_command("cat filterparam.txt | grep '.js$' > jsfiles.txt")
    run_command("cat filterparam.txt | grep '.json$' > jsonfiles.txt")

def deduplicate_js_files():
    """Deduplicate JavaScript files."""
    logging.info("Deduplicating JavaScript files...")
    run_command("cat jsfiles.txt | uro | anew jsfiles.txt")

def analyze_js_files_with_secret_finder():
    """Analyze each JavaScript file for secrets using SecretFinder."""
    logging.info("Analyzing JavaScript files with SecretFinder...")
    try:
        with open("jsfiles.txt", "r") as jsfiles:
            for url in jsfiles:
                url = url.strip()
                if url:
                    logging.info(f"Analyzing {url} for secrets...")
                    run_command(f"python3 ~/SecretFinder/SecretFinder.py -i {url} -o cli >> secret.txt", capture_output=False)
    except FileNotFoundError:
        logging.error("File jsfiles.txt not found. Ensure previous steps completed successfully.")

def display_banner():
    banner =    "=============================================="
    banner += "\n           Welcome to gather_0_v1            "
    banner += "\n     A Powerful Tool for Security Research    "
    banner += "\n                   Developed by the_shadow_0  "
    banner += "\n=============================================="
    print(banner)

def main():
    """Main function to run each task in sequence."""
    display_banner()
    
    create_subdomains_file()
    filter_alive_subdomains()
    gather_parameters()
    filter_parameters()
    categorize_files()
    deduplicate_js_files()
    analyze_js_files_with_secret_finder()
    
    logging.info("All tasks completed! Files have been created.")
    logging.info("Happy Hacking ... \n")

if __name__ == "__main__":
    main()
