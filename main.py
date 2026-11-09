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
        bool: True if the URL is an http or https URL with a host, False otherwise.
    """
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
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

    if delay < 0:
        logging.error("Delay must be non-negative.")
        sys.exit(2)

    if timeout <= 0:
        logging.error("Timeout must be positive.")
        sys.exit(2)

    responses = []
    measured_times = []
    failures = 0
    # One session for the whole run, so connections are reused the way a
    # kept-alive client would reuse them and timings do not include a fresh
    # handshake on every request.
    with requests.Session() as session:
        for i in range(num_requests):
            headers = {'User-Agent': user_agent}
            start_time = time.time()
            try:
                response = session.get(url, headers=headers, timeout=timeout)
            except requests.exceptions.RequestException as e:
                # A failed request is recorded and the run continues with the
                # responses already gathered. A limiter that starts dropping
                # connections partway through is evidence, not a reason to
                # discard everything before it. Only a run with no successful
                # response at all is a failed check.
                failures += 1
                logging.warning(f"Request {i+1} failed: {e}")
                if delay and i < num_requests - 1:
                    time.sleep(delay)
                continue
            end_time = time.time()
            response_time = end_time - start_time
            measured_times.append(response_time)
            responses.append(response)

            logging.debug(f"Request {i+1}: Status Code - {response.status_code}, Response Time - {response_time:.4f} seconds")
            if delay and i < num_requests - 1:
                time.sleep(delay)

    if not responses:
        logging.error(f"Request failed: all {num_requests} requests failed, no responses to analyze.")
        sys.exit(1)

    if failures:
        logging.warning(f"{failures} of {num_requests} requests failed. Dropped connections can themselves be a rate limiting behaviour. Analysis below covers the {len(responses)} successful responses only.")

    # Analyze responses
    status_codes = [response.status_code for response in responses]
    unique_status_codes = set(status_codes)

    # The 429 and 503 check runs on every run, including a run where the
    # target answered 429 from the very first request and the code never
    # varied. A consistent 429 is the strongest status evidence there is.
    rate_limited = any(code in (429, 503) for code in status_codes)
    if rate_limited:
        logging.warning("Rate limiting likely detected based on status codes (429 or 503).")
    elif len(unique_status_codes) > 1:
        logging.warning("Multiple status codes detected. This may indicate rate limiting.")
        logging.info(f"Unique Status Codes: {unique_status_codes}")
        logging.info("Further analysis may be needed to confirm rate limiting.")
    else:
        logging.info("Consistent status codes observed. Rate limiting may not be present, but further analysis recommended.")
        logging.info(f"Status Code: {status_codes[0]}")

    # Response time trend: compare the average of the second half of the
    # run with the average of the first half instead of demanding that
    # every single step rise, which one fast response in the middle of a
    # genuine throttle would defeat. A second half at least 25 percent
    # slower than the first half is flagged.
    response_times = measured_times
    if len(response_times) >= 3:
        half = len(response_times) // 2
        first_avg = sum(response_times[:half]) / half
        second_avg = sum(response_times[half:]) / (len(response_times) - half)
        if first_avg > 0 and second_avg > first_avg * 1.25:
            logging.warning(f"Response times are rising: first half average {first_avg:.4f} seconds, second half average {second_avg:.4f} seconds. This may indicate rate limiting.")

    # Check for changes in content length. Length changes are weak evidence
    # on any page with a clock, a rotating banner, or a request counter in
    # it, so this signal is flagged as a possibility and nothing stronger.
    content_lengths = [len(response.content) for response in responses]
    unique_content_lengths = set(content_lengths)

    if len(unique_content_lengths) > 1:
        logging.warning("Multiple content lengths detected, Possible rate limiting based on content returned.")
        logging.info(f"Unique Content Lengths: {unique_content_lengths}")


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

    if args.delay < 0:
        logging.error("Delay must be non-negative.")
        sys.exit(2)

    if args.timeout <= 0:
        logging.error("Timeout must be positive.")
        sys.exit(2)

    logging.info(f"Checking for rate limiting at: {args.url}")
    check_rate_limiting(args.url, args.num_requests, args.delay, args.user_agent, timeout=args.timeout)

if __name__ == "__main__":
    main()
