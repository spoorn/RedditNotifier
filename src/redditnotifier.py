from jproperties import Properties
from email.mime.text import MIMEText
from collections import deque
import requests
import json
import time
import logging
import sys
import smtplib
import traceback
import re
import os

config = Properties()
config_filename = "config.properties"
access_token = None
log = None
user = None
email_retries = 10

""" Setup logging """
def setup_logging():
    global log
    log = logging.getLogger()
    log.setLevel(logging.INFO)

    # Output to stdout console
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)

""" Connects to email server via SMTP """
def connect_email():
    email_server = config.get("email_server").data
    for i in range(email_retries):
        try:
            global server
            log.info("Connecting to email server...")
            passw = config.get("sender_password").data
            server = smtplib.SMTP(email_server, 587)
            server.ehlo()
            server.starttls()
            server.login(user, passw)
            log.info("Logged in...")
            return server
        except Exception as ex:
            traceback.print_exc()
            log.warn("Could not connect to email, retrying after 5s...")
            time.sleep(5)
    log.error('Could not connect to SENDER email server!  SMTP is labeled as a "Less Secure" app, so check the SENDER\'s email settings to make sure those apps are allowed access.')

""" Email recipients """
def act(regex, listing):
    global server
    permalink = listing["data"]["permalink"]
    subreddit = listing["data"]["subreddit_name_prefixed"]
    title = listing["data"]["title"]
    message = MIMEText(f"https://www.reddit.com{permalink}")
    message['Subject'] = f"Found match for [{regex}] with title {title} on {subreddit}"
    message['From'] = user
    to_list = config.get("recipient_emails").data.split(",")
    for i in range(email_retries):
        try:
            [server.sendmail(user, to_entry, message.as_string()) for to_entry in to_list]
        except (smtplib.SMTPSenderRefused, smtplib.SMTPServerDisconnected) as e:
            log.error(e)
            log.info("Attempting to reconnect smtp...")
            server = connect_email()
    log.info("Sent notification [" + message.get_payload() + "] to " + str(to_list))

def getUserAgentHeaders():
    return {'User-Agent': 'redditnotifier:org.spoorn:v1.0'}

def getToken(api_key, secret_key, headers, retries):
    auth = requests.auth.HTTPBasicAuth(api_key, secret_key)

    data = {
        'grant_type': 'client_credentials'
    }

    log.info("Fetching OAuth2 access token...")
    for i in range(retries):
        # send our request for an OAuth token
        res = requests.post('https://www.reddit.com/api/v1/access_token',
                        auth=auth, data=data, headers=headers)

        if res.status_code == 200:
            # convert response to JSON and pull access_token value
            return res.json()['access_token']
        log.warn("Failed to get access token, retrying...")
        time.sleep(5)

    log.error("Failed to fetch OAuth2 access token within retries")
    raise Exception("Failed to fetch access token within retries")
    

def getListings(subreddit, limit, old_headers, last_post, retries):
    global access_token
    # add authorization to our headers dictionary
    headers = {**old_headers, **{'Authorization': f"bearer {access_token}"}}

    if last_post is not None:
        params = {
            'limit': limit,
            'before': last_post,
            'show': 'all'
        }
    else:
        params = {
            'limit': limit,
            'show': 'all'
        }

    for i in range(retries):
        try:
            ret = requests.get(f"https://oauth.reddit.com/r/{subreddit}/new",
                            params=params, headers=headers)
            if ret.status_code != 200:
                log.warn(f"Got error status when querying listings {ret.status_code}, refreshing OAuth2 token...")
                access_token = getToken(api_key, secret_key, old_headers, access_token_retries)
                headers = {**old_headers, **{'Authorization': f"bearer {access_token}"}}
                time.sleep(5)
                continue
            return ret
        except:
            log.warn("Failed to get listings, retrying...")
            time.sleep(5)
            continue
    raise Exception("Could not get listings within retries!")

def check_matches(regex, listings):
    case_insensitive = config.get("case_insensitive")
    keyword = None
    if (case_insensitive):
        keyword = re.compile(regex, re.I)
    else:
        keyword = re.compile(regex)
    titles = [x["data"]["title"] for x in listings]
    new_listings = [x["data"]["title"] + "\n\t\thttps://www.reddit.com" + x["data"]["permalink"] for x in listings]
    log.info(f"New Listings:\n\t" + '\n\t'.join(new_listings))

    i = 0
    for title in titles:
        if re.search(keyword, title) is not None:
            log.info(f"Found a matching listing: {title}")
            act(regex, listings[i])
        i += 1


if __name__ == "__main__":
    setup_logging()
    with open(os.path.dirname(__file__) + "/../" + config_filename, 'rb') as config_file:
        config.load(config_file)
    user = config.get("sender_username").data
    assert user is not None
    access_token_retries = int(config.get("access_token_retries").data)
    listings_query_retries = int(config.get("listings_query_retries").data)
    limit = config.get("listings_per_check").data
    sleep_interval = int(config.get("check_listings_interval").data)
    regex = config.get("listings_regex").data
    subreddit = config.get("subreddit").data
    api_key = config.get("api_key").data
    secret_key = config.get("secret_key").data
    email_retries = int(config.get("email_login_retries").data)
    connect_email()
    headers = getUserAgentHeaders()


    try:
        access_token = getToken(api_key, secret_key, headers, access_token_retries)
        last_post = None

        i = 0
        num_checks_retro_check = int(config.get("num_checks_retro_check").data)
        num_pages_memory = int(config.get("num_pages_memory").data) * int(limit)
        last_names = deque([])
        while 1:
            #log.info(f"deque size={len(last_names)}")
            if (i == num_checks_retro_check):
                #log.info("retro check")
                ret = getListings(subreddit, limit, headers, None, listings_query_retries)
                retro_listings = ret.json()["data"]["children"]
                listings = [x for x in retro_listings if x["data"]["name"] not in last_names]
                #log.info("last_names: " + str(last_names))
                #log.info("listings: " + str(listings))
                i = 0
            elif last_post is not None:
                #log.info("regular check")
                ret = getListings(subreddit, limit, headers, last_post, listings_query_retries)
                #log.info(json.dumps(ret.json(), indent=2))
                new_listings = ret.json()["data"]["children"]
                listings = [x for x in new_listings if x["data"]["name"] not in last_names]
                if (len(new_listings) != len(listings)):
                    new_listings_names = [x["data"]["name"] for x in new_listings]
                    log.warn("Got new listings from Reddit, but we've already seen these!")
                    log.warn(f"Reddit New Listing names: {new_listings_names}")
                    log.warn(f"Current names registry: {last_names}")
                    diff_listings = [x["data"]["title"] for x in new_listings if x in last_names]
                    log.warn(f"Difference: {diff_listings}")
                i += 1
            else:
                ret = getListings(subreddit, int(limit) * 2, headers, None, listings_query_retries)
                listings = ret.json()["data"]["children"]
                i += 1
            if (len(listings) > 0):
                # Left is the head of the queue, so we insert the new listings to head of queue, and pop the end
                last_post = listings[0]["data"]["name"]
                for listing in reversed(listings):
                    last_names.appendleft(listing["data"]["name"])
                    if len(last_names) > num_pages_memory:
                        last_names.pop()
                #log.info("last_post: " + listings[0]["data"]["title"])
                check_matches(regex, listings)
            time.sleep(sleep_interval)
    except:
        traceback.print_exc()
        log.info("Exiting")
        quit()

