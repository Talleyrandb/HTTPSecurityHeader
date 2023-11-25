import argparse
import http.client
import re
import socket
import ssl
import urllib.parse
import os
import sys

def make_connection(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        scheme = parsed_url.scheme
        hostname = parsed_url.netloc
        path = parsed_url.path if parsed_url.path else "/"

        if scheme == "https":
            connection = http.client.HTTPSConnection(hostname, context=ssl.create_default_context())
        else:
            connection = http.client.HTTPConnection(hostname)

        return connection, path
    except Exception as e:
        print("\033[91mConnection Error:", e, "\033[0m")
        sys.exit(1)

def print_colored_message(message, color):
    colors = {
        "red": "\033[91m",
        "blue": "\033[94m",
        "default": "\033[0m",
    }
    print(f"{colors[color]}{message}{colors['default']}")

def validate_headers(response):
    # Validate X-Frame-Options header
    x_frame_options = response.getheader("X-Frame-Options", "")
    if x_frame_options not in ['DENY', 'SAMEORIGIN']:
        print_colored_message("Validation Error: X-Frame-Options is not set to 'DENY' or 'SAMEORIGIN'", "red")
    else:
        print_colored_message(f"X-Frame-Options is set correctly, is set as {x_frame_options}", "blue")

    # Validate X-XSS-Protection header
    x_xss_protection = response.getheader("X-XSS-Protection", "")
    if x_xss_protection != '0':
        print_colored_message(f"Validation Error: X-XSS-Protection is not set to '0' is set as {x_xss_protection}", "red")
    else:
        print_colored_message("X-XSS-Protection is set correctly", "blue")

    # Validate X-Content-Type-Options header
    x_content_type_options = response.getheader("X-Content-Type-Options", "")
    if x_content_type_options != 'nosniff':
        print_colored_message("Validation Error: X-Content-Type-Options is not set to 'nosniff'", "red")
    else:
        print_colored_message(f"X-Content-Type-Options is set correctly, is set as {x_content_type_options}", "blue")

    # Validate strict-Transport-Security header
    hsts_header = response.getheader("Strict-Transport-Security", "")
    if 'includeSubDomains' not in hsts_header or 'preload' not in hsts_header:
        print_colored_message("Validation Error: HSTS is missing 'includeSubDomains' and/or 'preload'", "red")
    else:
        print_colored_message("HSTS is set correctly", "blue")

    # Extract max-age value and check if it's equal or higher than 31536000
    max_age_match = re.search(r"max-age=(\d+)", hsts_header)
    if max_age_match:
        max_age_value = int(max_age_match.group(1))
        if max_age_value < 31536000:
            print_colored_message("Validation Error: HSTS max-age is less than 31536000", "red")
        else:
            print_colored_message("HSTS max-age is set correctly", "blue")
    else:
        print_colored_message(f"Validation Error: HSTS is missing max-age, is set as {max_age_value}", "red")

    # Validate Content-Security-Policy header
    content_security_policy = response.getheader("Content-Security-Policy", "")
    if 'unsafe-inline' in content_security_policy or 'unsafe-eval' in content_security_policy:
        print_colored_message("Validation Error: Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval'", "red")
    else:
        print_colored_message("Content-Security-Policy is set correctly", "blue")

    # Validate X-Permitted-Cross-Domain-Policies header
    x_permitted_cross_domain_policies = response.getheader("X-Permitted-Cross-Domain-Policies", "")
    if not x_permitted_cross_domain_policies:
        print_colored_message(f"Validation Error: X-Permitted-Cross-Domain-Policies is not set, is set as {x_permitted_cross_domain_policies}", "red")
    else:
        print_colored_message("X-Permitted-Cross-Domain-Policies is set correctly", "blue")

    # Validate Referrer-Policy header
    referrer_policy = response.getheader("Referrer-Policy", "")
    if not referrer_policy:
        print_colored_message("Validation Error: Referrer-Policy is not set", "red")
    else:
        print_colored_message("Referrer-Policy is set correctly", "blue")

    # Validate Expect-CT header
    expect_ct = response.getheader("Expect-CT", "")
    if expect_ct:
        print_colored_message(f"Validation Warning: Expect-CT attribute is unnecessary, but is set as {expect_ct}", "blue")
    else:
        print_colored_message("Validation Error: Expect-CT attribute is unnecessary", "red")

    # Validate Permissions-Policy header
    permissions_policy = response.getheader("Permissions-Policy", "")
    if not permissions_policy:
        print_colored_message("Validation Error: Permissions-Policy is not set", "red")
    else:
        print_colored_message("Permissions-Policy is set correctly", "blue")

    # Validate Cross-Origin-Embedder-Policy header
    cross_origin_embedder_policy = response.getheader("Cross-Origin-Embedder-Policy", "")
    if not cross_origin_embedder_policy:
        print_colored_message("Validation Error: Cross-Origin-Embedder-Policy is not set", "red")
    else:
        print_colored_message("Cross-Origin-Embedder-Policy is set correctly", "blue")

    # Validate Cross-Origin-Resource-Policy header
    cross_origin_resource_policy = response.getheader("Cross-Origin-Resource-Policy", "")
    if 'same-site' not in cross_origin_resource_policy:
        print_colored_message("Validation Error: Cross-Origin-Resource-Policy is not set to 'same-site'", "red")
    else:
        print_colored_message(f"Cross-Origin-Resource-Policy is set correctly, is set as {cross_origin_resource_policy}", "blue")

    # Validate Cross-Origin-Opener-Policy header
    cross_origin_opener_policy = response.getheader("Cross-Origin-Opener-Policy", "")
    if 'same-site' not in cross_origin_opener_policy:
        print_colored_message("Validation Error: Cross-Origin-Opener-Policy is not set to 'same-site'", "red")
    else:
        print_colored_message("Cross-Origin-Opener-Policy is set correctly", "blue")

    # Validate Set-Cookie header
    set_cookie = response.getheader("Set-Cookie", "")
    if 'HttpOnly' not in set_cookie or 'Secure' not in set_cookie or 'SameSite' not in set_cookie:
        print_colored_message("Validation Error: Set-Cookie is missing HttpOnly, Secure, or SameSite attributes", "red")
    else:
        print_colored_message("Set-Cookie is set correctly", "blue")

    # Validate Content-Type header
    content_type = response.getheader("Content-Type", "")
    if 'charset=UTF-8' not in content_type:
        print_colored_message("Validation Error: Content-Type is not set to 'charset=UTF-8'", "red")
    else:
        print_colored_message(f"Content-Type is set correctly, is set as {content_type}", "blue")

    # Validate Server header
    server = response.getheader("Server", "")
    if not server:
        print_colored_message("Server header is hidden", "blue")
    else:
        print_colored_message(f"Validation Error: Server header is set uncorrectly as {server}", "red")

    # Validate X-Powered-By header
    x_powered_by = response.getheader("X-Powered-By", "")
    if not x_powered_by:
        print_colored_message("X-Powered-By header is hidden", "blue")
    else:
        print_colored_message(f"Validation Error: X-Powered-By header is set uncorrectly as {x_powered_by}", "red")

    # Validate X-AspNetMvc-Version header
    x_aspnetmvc_version = response.getheader("X-AspNetMvc-Version", "")
    if not x_aspnetmvc_version:
        print_colored_message("X-AspNetMvc-Version header is hidden", "blue")
    else:
        print_colored_message(f"Validation Error: X-AspNetMvc-Version header is set uncorrectly as {x_aspnetmvc_version}", "red")

def main():
    parser = argparse.ArgumentParser(description="HTTP Headers Validator")
    parser.add_argument("url", type=str, help="URL to validate")
    args = parser.parse_args()

    connection, path = make_connection(args.url)

    try:
        connection.request("GET", path)
        response = connection.getresponse()
        validate_headers(response)
    finally:
        connection.close()

if __name__ == "__main__":
    main()  
#Desarrollado por Dalmiro Bermudez
