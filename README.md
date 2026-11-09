# vscan-rate-limiting-checker

Checks whether rate limiting is implemented on an endpoint by sending a series of GET requests over one reused session connection and analyzing the responses.

What the verdict is based on:

- A 429 or 503 status in any response is reported as rate limiting likely detected. This includes a target that answers 429 from the very first request.
- More than one distinct status code across the run, without a 429 or 503, is reported as a possible indication that needs further analysis.
- A consistent status code with no 429 or 503 is reported as rate limiting may not be present.
- If the average response time of the second half of the run is at least 25 percent higher than the first half (runs of 3 or more requests), rising response times are flagged as a possible indication.
- More than one distinct content length is flagged as a possibility only. Dynamic pages can change length without any limiter.
- A request that fails mid-run does not discard the run. Failures are counted and reported, and the successful responses are still analyzed. Dropped connections can themselves be a limiting behaviour. If every request fails, the check exits non-zero.

## Install

`git clone https://github.com/ShadowGuard-AI/vscan-rate-limiting-checker`

Requires Python 3 and the package in requirements.txt (requests).

## Usage

`python3 main.py URL [-n NUM_REQUESTS] [-d DELAY] [-v] [-u USER_AGENT] [--timeout TIMEOUT]`

The URL must be an http or https URL. Example: `python3 main.py http://127.0.0.1:8080/login -n 20 -d 0.05`

## Parameters

- `url`: The URL to check for rate limiting.
- `-h`: Show help message and exit
- `-n`, `--num_requests`: The number of requests to send. Default is 10. Must be at least 1.
- `-d`, `--delay`: Delay between requests in seconds. Default is 0.1. Must be non-negative.
- `-v`, `--verbose`: Enable verbose output (debug logging).
- `-u`, `--user_agent`: Custom user agent string.
- `--timeout`: Timeout for each request in seconds. Default is 10. Must be positive.

Invalid arguments (bad URL, request count below 1, negative delay, non-positive timeout) exit non-zero before any request is sent.

## License

MIT (see the LICENSE file)
