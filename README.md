# heyjack53
This is a script to automate the takeover process for domains that have route53 dangling nameserver records.

Based on https://github.com/shivsahni/NSBrute

 ## Installing

 Clone the repo
    
    $ git clone git@github.com:brunobcestari/heyjack53.git
    
 install it using pip
    
    $ cd heyjack53
    $ pip install .

 ## Usage

 You can authenticate to your AWS account either using the `aws_access_key` and `aws_secret_access_key` (and `aws_session_token` if needed) or providing the `profile_name` for your stored credentials in ~/.aws/credentials

 Use 
 * `-a` or `--access` for aws_access_key
 * `-s` or `--secret` for aws_secret_access_key
 * `-t` or `--token` for aws_session_token

 OR

 * `-p` or `--profile` for aws profile_name

 ### Domain Input Options

 You can specify domains to check/hijack in three ways:

 * `-d` or `--domain` for a single domain
 * `-l` or `--list` for a comma-separated list of domains
 * `-f` or `--file` for a file containing one domain per line

 ### Operation Modes

 * Default mode: Check vulnerability and attempt hijack
 * `-c` or `--check-only`: Only check if domains are vulnerable without attempting hijack

 ### Additional Options

 * `-v` or `--verbose`: Increase verbosity
 * `--force`: Continue even if domain currently resolves
 * `-y` or `--yes`: Automatic YES answer when prompted
 * `-ns` or `--nameserver`: Manually specify nameservers

 ### Examples:

 Check a single domain for vulnerability:

    $ heyjack53 -d example.com -p my_profile_name -c

 Hijack a single domain:

    $ heyjack53 -d example.com -p my_profile_name

 Check multiple domains from a comma-separated list:

    $ heyjack53 -l "example1.com,example2.com,example3.com" -p my_profile_name -c

 Process domains from a file:

    $ heyjack53 -f domains.txt -p my_profile_name -y

 ## Key Improvements

 * **Fixed nameserver matching logic**: Now correctly requires ALL target nameservers to match (using `issubset()` instead of `intersection()`)
 * **Multi-domain support**: Process multiple domains via list or file input
 * **Check-only mode**: Test vulnerability without attempting hijack
 * **Better error handling**: More robust error handling and logging
 * **Optimized cleanup**: Improved zone cleanup logic with better throttling handling
 * **Code structure**: Refactored into modular functions for better maintainability
