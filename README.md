# RedditNotifier
Simple python script that queries and scrapes a Reddit subreddit for new listings that match a given regex (regular expression).  The script will print out any matching listings, and can be setup to notify via email or text whenever a match is found.


## Instructions

### Installation
Clone repository: `git clone https://github.com/spoorn/RedditNotifier.git`  
Or   
Download and extract zip under Releases: https://github.com/spoorn/RedditNotifier/releases

### Prerequisites
1. The python script uses various libraries which can be installed via `pip install <package>`.  A majority of these should come by default with Python.  Non-standard packages:
    - [jproperties](https://pypi.org/project/jproperties/)
2. The script accesses Reddit APIs to fetch subreddit listings.  You will need to provide an API Key and Secret Key for authentication:
    - Go to https://www.reddit.com/prefs/apps/
    - Click `create another app...` at the bottom
    - Type in any name, and description
    - Select type `script`
    - redirect url can be anything as it's unused in the script, but required to create an app on reddit.  You can use `https://github.com/spoorn/RedditNotifier`
    - API Key will be under **"personal use script"**
    - Secret Key will be after **"secret"**
    - These keys will be needed in the configurations below 


### Configurations
All setup and configurations are inputted in `config.properties` (see [properties file](https://github.com/spoorn/RedditNotifier/blob/main/config.properties) for documentation).

This script uses SMTP to send messages/text other emails/phone numbers.  You will need to provide an email for the SENDER (Gmail has been tested and works).  Recommend to use a non-important email as credentials will be stored in a configuration file - you can create a new dummy email.  The SENDER email is logged in via SMTP, so depending on the email server, you may need to allow access from "Less Secure Apps" (see https://support.google.com/accounts/answer/6010255 if you are using Gmail).

> ⚠️Note: If you are running the script from a server such as Google Compute Engine, or you don't want to store your password directly in the config file, you can make use of an App Password instead: https://support.google.com/accounts/answer/185833?hl=en

> ⚠️ Note: If you are trying to notify a phone via text message, be sure to enable MMS messaging on your phone.  If you are trying to notify via email, double check the Spam folder and some email servers may mark the email as spam.

### Running the script
`cd` into the directory where you installed, then run `python src/redditnotifier.py` or `python3 src/redditnotifier.py`

`Ctrl + C` to terminate the script.
