use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Duration;
use std::{fs, io, thread};

use java_properties::PropertiesError;
use lazy_static::lazy_static;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::{debug, error, info, warn};
use regex::{Regex, RegexBuilder};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use slice_deque::SliceDeque;

static CONFIG_FILE: &'static str = "config.properties";
static MY_USER_AGENT: &'static str = "redditnotifier:org.spoorn:v1.0";
static LISTING_SNAPSHOT_FILEPATH: &'static str = "run/snapshots/listing_snapshot.txt";

lazy_static! {
    static ref CLIENT: Client = reqwest::blocking::Client::new();
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: String,
}

/// Initialize and setup logger
fn setup_logging() -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Info)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

fn read_config() -> Result<HashMap<String, String>, PropertiesError> {
    let config_file = File::open(CONFIG_FILE)?;
    java_properties::read(BufReader::new(config_file))
}

fn connect_email(config: &HashMap<String, String>) -> SmtpTransport {
    let email_server = get_config_or_error(&config, "email_server");
    let email_login_retries = get_usize_from_config(&config, "email_retries");
    let sender_username = get_config_or_error(&config, "sender_username");
    let sender_password = get_config_or_error(&config, "sender_password");

    for _ in 0..email_login_retries {
        info!("Connecting to email server...");
        let creds = Credentials::new(sender_username.to_string(), sender_password.to_string());
        let mailer = SmtpTransport::relay(email_server)
            .unwrap()
            .credentials(creds)
            .build();
        match mailer.test_connection() {
            Ok(b) => {
                if b {
                    info!("Successfully logged in...");
                    return mailer;
                } else {
                    error!("Failed to connect to email. Retrying in 5s...");
                    thread::sleep(Duration::from_secs(5));
                }
            }
            Err(e) => {
                error!("Could not connect to email: {}\nRetrying in 5s...", e);
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
    panic!("Could not connect to SENDER email server!  SMTP is labeled as a \"Less Secure\" app, so check the SENDER\'s email settings to make sure those apps are allowed access.")
}

fn act(
    config: &HashMap<String, String>,
    mailer: &mut SmtpTransport,
    regex: &Regex,
    listing: &Value,
    title: &str,
    permalink: &String,
) {
    let sender_username = get_config_or_error(&config, "sender_username");
    let recipients = get_config_or_error(&config, "recipient_emails");
    let retries = get_usize_from_config(&config, "email_retries");

    let subreddit = listing
        .get("data")
        .unwrap()
        .get("subreddit_name_prefixed")
        .unwrap()
        .as_str()
        .unwrap();
    let regex_str = regex.as_str();
    let body = format!("{title} - https://www.reddit.com{permalink}");
    let mut builder = Message::builder()
        .subject(format!("Found match for [{regex_str}] on {subreddit}"))
        .from(sender_username.parse().unwrap());

    for recipient in recipients.split(",").into_iter() {
        // We reassign the outer variable since to() takes ownership of self
        builder = builder.to(recipient.parse().unwrap());
    }

    let message = builder
        .body(body.clone())
        .expect("Email message was not properly constructed.");

    for _ in 0..retries {
        match mailer.send(&message) {
            Ok(_) => {
                info!("Sent notification [{body}] to {recipients}");
                break;
            }
            Err(e) => {
                error!("Failed to send message {}", e);
                info!("Attempting to reconnect SMTP...");
                *mailer = connect_email(config);
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

fn get_access_token(api_key: &str, secret_key: &str, retries: usize) -> String {
    let data = ("grant_type", "client_credentials");
    let headers = get_user_agent_headers();
    for _ in 0..retries {
        // send our request for an OAuth token
        let res = CLIENT
            .post("https://www.reddit.com/api/v1/access_token")
            .basic_auth(api_key, Some(secret_key))
            .headers(headers.clone())
            .query(&[data])
            .send();

        match res {
            Ok(response) if response.status() == StatusCode::OK => {
                info!("Successfully fetched OAuth2 access token");
                return response
                    .json::<AccessTokenResponse>()
                    .expect("Could not deserialize access token response!")
                    .access_token;
            }
            _ => {
                warn!("Failed to get OAuth2 access token, retrying after 5s...");
                thread::sleep(Duration::from_secs(5));
            }
        }
    }

    panic!("Failed to fetch access token within retries")
}

fn get_listings(
    config: &HashMap<String, String>,
    limit: usize,
    headers: &mut HeaderMap,
    last_post: &Option<String>,
    access_token: &mut String,
) -> Value {
    // Configs
    let subreddit = get_config_or_error(&config, "subreddit");
    let retries = get_usize_from_config(&config, "listings_query_retries");

    headers.insert(
        "Authorization",
        format!("bearer {access_token}").parse().unwrap(),
    );

    // Param data
    let mut params = Map::new();
    params.insert(String::from("limit"), Number::from(limit).into());
    params.insert(String::from("show"), String::from("all").into());

    if let Some(post) = last_post {
        params.insert(String::from("before"), post.to_string().into());
    }

    for _ in 0..retries {
        let res = CLIENT
            .get(format!("https://oauth.reddit.com/r/{subreddit}/new"))
            .headers(headers.clone())
            .query(&params)
            .send();

        match res {
            Ok(response) => {
                if response.status() == StatusCode::OK {
                    debug!("Successfully fetched listings");
                    return response
                        .json::<Value>()
                        .expect("Could not deserialize listings response!");
                } else {
                    warn!(
                        "Got error status when querying listings {}, refreshing OAuth2 token...",
                        response.status()
                    );
                    // refresh access token
                    *access_token = get_access_token(
                        get_config_or_error(&config, "api_key"),
                        get_config_or_error(&config, "secret_key"),
                        get_usize_from_config(&config, "access_token_retries"),
                    );
                    headers.insert(
                        "Authorization",
                        format!("bearer {access_token}").parse().unwrap(),
                    );
                }
            }
            _ => {
                warn!("Failed to query listings, retrying...");
            }
        }

        // error case
        thread::sleep(Duration::from_secs(5));
    }

    panic!("Could not get listings within retries!")
}

fn check_matches(
    config: &HashMap<String, String>,
    mailer: &mut SmtpTransport,
    regex: &Regex,
    listings: Vec<&Value>,
) {
    let mut titles: Vec<&str> = Vec::new();
    let mut links: Vec<String> = Vec::new();
    for listing in listings.iter() {
        let data = listing.get("data").unwrap();
        let title = data.get("title").unwrap().as_str().unwrap();
        titles.push(title);
        let permalink = data.get("permalink").unwrap().as_str().unwrap();
        links.push(format!("{title}\n\t\thttps://www.reddit.com{permalink}"))
    }
    info!("New Listings:\n\t{}", links.join("\n\t"));

    for (i, title) in titles.iter().enumerate() {
        if regex.is_match(title) {
            info!("Found a matching listing: {}", title);
            act(config, mailer, regex, listings[i], title, &links[i]);
        }
    }
}

fn get_user_agent_headers() -> HeaderMap {
    let mut res = HeaderMap::new();
    res.insert(USER_AGENT, HeaderValue::from_static(MY_USER_AGENT));
    res
}

fn load_snapshot(listing_ids_snapshot: &mut SliceDeque<String>, limit: usize) {
    let path = Path::new(LISTING_SNAPSHOT_FILEPATH);
    if path.is_file() {
        let path_str = path
            .canonicalize()
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap();
        info!("Loading snapshot from {}", path_str);
        match read_lines(path) {
            Ok(lines) => {
                for line in lines {
                    append_to_slice_deque(listing_ids_snapshot, limit, line.unwrap());
                }
            }
            _ => panic!("Could not read snapshots from {}", path_str),
        }
        info!("Loaded snapshot IDs: {:?}", listing_ids_snapshot);
    }
}

fn save_snapshot(listing_ids_snapshot: &mut SliceDeque<String>) {
    if !listing_ids_snapshot.is_empty() {
        let path = Path::new(LISTING_SNAPSHOT_FILEPATH);
        info!(
            "Saving a snapshot of last {} processed listings",
            listing_ids_snapshot.len()
        );
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut snapshot_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .unwrap();
        for listing in listing_ids_snapshot {
            writeln!(&mut snapshot_file, "{}", &listing[..])
                .expect("Could not write to snapshot file");
        }
        info!(
            "Saved listings snapshot to {}",
            path.canonicalize()
                .unwrap()
                .into_os_string()
                .into_string()
                .unwrap()
        )
    }
}

fn append_to_slice_deque<S: AsRef<str>>(slice_deque: &mut SliceDeque<S>, limit: usize, item: S) {
    slice_deque.push_back(item);
    if slice_deque.len() > limit {
        slice_deque.pop_front();
    }
}

fn prepend_to_slice_deque<S: AsRef<str>>(slice_deque: &mut SliceDeque<S>, limit: usize, item: S) {
    slice_deque.push_front(item);
    if slice_deque.len() > limit {
        slice_deque.pop_back();
    }
}

fn get_new_listings(listings: Value) -> Vec<Value> {
    listings
        .get("data")
        .expect("Listings is missing 'data' field")
        .get("children")
        .expect("Listings is missing 'data.children' field")
        .as_array()
        .expect("Listings 'data.children' was not an array")
        .to_vec()
}

fn get_unseen_listings(listings: Vec<Value>, last_names: &SliceDeque<String>) -> Vec<Value> {
    listings
        .into_iter()
        .filter(|x| {
            !last_names.contains(
                &x.get("data")
                    .unwrap()
                    .get("name")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect::<Vec<Value>>()
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(BufReader::new(file).lines())
}

fn get_config_or_error<'a>(config: &'a HashMap<String, String>, key: &'a str) -> &'a str {
    config.get(key).expect(&format!(
        "{key} was not correctly specified in the properties file!"
    ))
}

fn get_usize_from_config(config: &HashMap<String, String>, key: &str) -> usize {
    get_config_or_error(&config, key)
        .parse::<usize>()
        .expect(&format!("{key} must be a positive integer"))
}

fn get_bool_from_config(config: &HashMap<String, String>, key: &str) -> bool {
    get_config_or_error(&config, key)
        .parse::<bool>()
        .expect(&format!("{key} must be 'true' or 'false'"))
}

fn main() {
    // Setup logging
    setup_logging().expect("Failed to setup logger");

    // Read config
    let config = read_config().expect(&format!("Failed to read config file at {CONFIG_FILE}"));
    debug!("read config: {:#?}", config);

    // Connect to email server
    let mut mailer = connect_email(&config);

    // Get Access Token
    let api_key = get_config_or_error(&config, "api_key");
    let secret_key = get_config_or_error(&config, "secret_key");
    let access_token_retries = get_usize_from_config(&config, "access_token_retries");
    let mut access_token = get_access_token(api_key, secret_key, access_token_retries);

    // Load last saved snapshot
    let limit = get_usize_from_config(&config, "listings_per_check");
    let mut listing_ids_snapshot = SliceDeque::new();
    load_snapshot(&mut listing_ids_snapshot, limit);

    // Loop to query listings and check for matches at intervals
    let num_checks_retro_check = get_usize_from_config(&config, "num_checks_retro_check");
    let num_pages_memory = get_usize_from_config(&config, "num_pages_memory") * limit;
    let listings_regex = RegexBuilder::new(get_config_or_error(&config, "listings_regex"))
        .case_insensitive(get_bool_from_config(&config, "case_insensitive"))
        .build()
        .expect("listings_regex is invalid");
    let mut last_names: SliceDeque<String> = SliceDeque::new(); // max size will be num_pages_memory
    let headers = &mut get_user_agent_headers();
    let mut last_post: Option<String> = None;
    let mut i = 0;
    loop {
        let ret;
        let listings: Vec<Value>;

        if i == num_checks_retro_check {
            debug!("Running retro check...");
            ret = get_listings(&config, limit, headers, &None, &mut access_token);
            let retro_listings = get_new_listings(ret);
            listings = get_unseen_listings(retro_listings, &last_names);
            i = 0;
        } else if last_post.is_some() {
            ret = get_listings(&config, limit, headers, &last_post, &mut access_token);
            let new_listings = get_new_listings(ret);
            listings = get_unseen_listings(new_listings.clone(), &last_names);

            if new_listings.len() != listings.len() {
                let new_listings_names: Vec<&str> = new_listings
                    .iter()
                    .map(|x| {
                        x.get("data")
                            .unwrap()
                            .get("name")
                            .unwrap()
                            .as_str()
                            .unwrap()
                    })
                    .collect();
                warn!("Got new listings from Reddit, but we've already seen these!");
                warn!("Reddit New Listing names: {:?}", new_listings_names);
                warn!("Current names registry: {:?}", last_names);
                let diff_listings: Vec<&str> = new_listings
                    .iter()
                    .map(|x| {
                        x.get("data")
                            .unwrap()
                            .get("title")
                            .unwrap()
                            .as_str()
                            .unwrap()
                    })
                    .filter(|&x| !last_names.contains(&x.to_string()))
                    .collect();
                warn!("Difference: {:?}", diff_listings);
            }
            i += 1;
        } else {
            ret = get_listings(&config, limit * 2, headers, &None, &mut access_token);
            listings = get_new_listings(ret);
            i += 1;
        }

        // Save last listing queried, so subsequent queries only check after the last post
        if !listings.is_empty() {
            last_post = Some(
                listings[0]
                    .get("data")
                    .unwrap()
                    .get("name")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }

        // Cross check listings with the snapshot loaded from file
        let mut new_listings = Vec::new();
        // Left is the head of the queue, so we insert the new listings to head of queue, and pop the end
        for k in (0..listings.len()).rev() {
            let listing = &listings[k];
            let data = listing.get("data").unwrap();
            if !listing_ids_snapshot
                .contains(&data.get("id").unwrap().as_str().unwrap().to_string())
            {
                new_listings.push(listing);
            }
            prepend_to_slice_deque(
                &mut last_names,
                num_pages_memory,
                data.get("name").unwrap().as_str().unwrap().to_string(),
            );
        }

        if !new_listings.is_empty() {
            for k in (0..new_listings.len()).rev() {
                let listing = new_listings[k];
                let post_id = listing
                    .get("data")
                    .unwrap()
                    .get("id")
                    .unwrap()
                    .as_str()
                    .unwrap();
                // We separately append to listing_ids_snapshot here instead of before the if condition because
                // listings can be received in different ordering, so we can't update listings and the snapshot
                // in one loop
                append_to_slice_deque(&mut listing_ids_snapshot, limit * 2, post_id.to_string());
            }

            check_matches(&config, &mut mailer, &listings_regex, new_listings);
            save_snapshot(&mut listing_ids_snapshot);
        }

        thread::sleep(Duration::from_secs(5));
    }
}
