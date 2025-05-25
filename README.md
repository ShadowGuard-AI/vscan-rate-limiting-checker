# vscan-rate-limiting-checker
Checks if rate limiting is implemented on sensitive endpoints by sending multiple requests in a short period and analyzing the responses. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-rate-limiting-checker`

## Usage
`./vscan-rate-limiting-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `-n`: The number of requests to send. Default is 10.
- `-d`: Delay between requests in seconds. Default is 0.1.
- `-v`: No description provided
- `-u`: Custom user agent string.

## License
Copyright (c) ShadowStrikeHQ
