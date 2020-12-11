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
 
 Then you need to provide the domain to be hijacked through the `-d` or `--domain` parameter
 
 ### Example:
 
    $ heyjack53 -d example.com -p my_profile_name
