import argparse
import requests
import time
import logging
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Checks if rate limiting is implemented on sensitive endpoints.")
    parser.add_argument("url", help="The URL to check for rate limiting.")
    parser.add_argument("-n", "--num_requests", type=int, default=10, help="The number of requests to send. Default is 10.")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay between requests in seconds. Default is 0.1.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-u", "--user_agent", type=str, default="vscan-rate-limiting-checker/1.0", help="Custom user agent string.")
    parser.add_argument("--timeout", type=float, default=10, help="Timeout for each request in seconds. Default is 10.")
    return parser.parse_args()

def is_valid_url(url):
    """
    Validates if the given URL is properly formatted.
    
    Args:
        url (str): The URL to validate.
    
    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def check_rate_limiting(url, num_requests, delay, user_agent, timeout=10):
    """
    Checks for rate limiting by sending multiple requests to the specified URL.

    Args:
        url (str): The URL to check.
        num_requests (int): The number of requests to send.
        delay (float): The delay between requests in seconds.
        user_agent (str): The user agent string to use for requests.

    Returns:
        None
    """

    if not is_valid_url(url):
        logging.error("Invalid URL provided.")
        sys.exit(1)

    if num_requests < 1:
        logging.error("Number of requests must be at least 1.")
        sys.exit(2)

    try:
        responses = []
        measured_times = []
        for i in range(num_requests):
            headers = {'User-Agent': user_agent}
            start_time = time.time()
            # Each request opens a fresh connection, with no session reuse, so the time I record includes DNS and the TLS handshake every round. A limiter keyed on connections rather than requests is also being fed one connection per request, which is not how a browser or a kept alive client would meet it.
            response = requests.get(url, headers=headers, timeout=timeout)
            end_time = time.time()
            response_time = end_time - start_time
            measured_times.append(response_time)
            responses.append(response)

            logging.debug(f"Request {i+1}: Status Code - {response.status_code}, Response Time - {response_time:.4f} seconds")
            time.sleep(delay)

        # Analyze responses
        status_codes = [response.status_code for response in responses]
        unique_status_codes = set(status_codes)

        if len(unique_status_codes) > 1:
            logging.warning("Multiple status codes detected. This may indicate rate limiting.")
            logging.info(f"Unique Status Codes: {unique_status_codes}")

            # Check for common rate limiting status codes (e.g., 429, 503)
            # This line only runs when more than one distinct status code appeared. A target that answers 429 from the very first request, because the caller was already over budget, produces one consistent code and lands in the branch below that reports limiting may not be present: the strongest possible evidence reads as the weakest.
            rate_limited = any(code in [429, 503] for code in status_codes)
            if rate_limited:
                logging.warning("Rate limiting likely detected based on status codes (429 or 503).")
            else:
                logging.info("Further analysis may be needed to confirm rate limiting.")


        else:
            logging.info("Consistent status codes observed. Rate limiting may not be present, but further analysis recommended.")
            logging.info(f"Status Code: {status_codes[0]}")

        # Judge only from the per request times measured above.
        response_times = measured_times

        #Check if response times are increasing which indicates rate limiting is in place
        # Monotonic across every single step is a strict demand on a noisy network. One fast response in the middle of a genuine throttle resets the verdict, and ordinary jitter on an unthrottled target can also produce a short rising run by chance at small request counts.
        increasing_response_times = len(response_times) > 1 and all(response_times[i] <= response_times[i+1] for i in range(len(response_times) -1))
        if increasing_response_times:
            logging.warning("Response times are consistently increasing. This may indicate rate limiting.")

        #Check for changes in content length
        content_lengths = [len(response.content) for response in responses]
        # Length changes are weak evidence on any page with a clock, a rotating banner, or a request counter in it. I flag the possibility and name nothing stronger, because this signal alone cannot separate a limiter's block page from ordinary dynamic content.
        unique_content_lengths = set(content_lengths)

        if len(unique_content_lengths) > 1:
                logging.warning("Multiple content lengths detected, Possible rate limiting based on content returned.")
                logging.info(f"Unique Content Lengths: {unique_content_lengths}")



    # One failed request anywhere in the run discards every response gathered before it and exits. A limiter that starts dropping connections halfway through, which is a real limiting behaviour, is reported as a failed check rather than as evidence.
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)



def main():
    """
    Main function to execute the rate limiting checker.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    if args.num_requests < 1:
        logging.error("Number of requests must be at least 1.")
        sys.exit(2)

    logging.info(f"Checking for rate limiting at: {args.url}")
    check_rate_limiting(args.url, args.num_requests, args.delay, args.user_agent, timeout=args.timeout)

if __name__ == "__main__":
    main()