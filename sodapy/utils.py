from collections.abc import Iterable
from typing import Any
import csv
from io import StringIO
import json
import re
import requests

from .constants import DEFAULT_API_PATH, OLD_API_PATH


# Utility methods
def raise_for_status(response):
    """
    Custom raise_for_status with more appropriate error message.
    """
    http_error_msg = ""

    if 400 <= response.status_code < 500:
        http_error_msg = f"{response.status_code} Client Error: {response.reason}"

    elif 500 <= response.status_code < 600:
        http_error_msg = f"{response.status_code} Server Error: {response.reason}"

    if http_error_msg:
        try:
            more_info = response.json().get("message")
        except ValueError:
            more_info = None
        if more_info and more_info.lower() != response.reason.lower():
            http_error_msg += f".\n\t{more_info}"
        raise requests.exceptions.HTTPError(http_error_msg, response=response)


def format_param(val: Any):
    """By default, the requests package will take params values that are lists etc. and include that key in the URL multiple times. This combines the values with commas, which seems to be the convention of the Socrata APIs."""

    if isinstance(val, Iterable) and not isinstance(val, str):
        return ",".join(val)

    return val


def clear_empty_values(args):
    """
    Scrap junk data from a dict.
    """
    result = {}
    for param in args:
        if args[param] is not None:
            result[param] = args[param]
    return result


def format_old_api_request(dataid=None, content_type=None):
    if dataid is not None:
        if content_type is not None:
            return f"{OLD_API_PATH}/{dataid}.{content_type}"
        return f"{OLD_API_PATH}/{dataid}"

    if content_type is not None:
        return f"{OLD_API_PATH}.{content_type}"

    raise Exception("This method requires at least a dataset_id or content_type.")


def format_new_api_request(dataid=None, row_id=None, content_type=None):
    if dataid is not None:
        if content_type is not None:
            if row_id is not None:
                return f"{DEFAULT_API_PATH}{dataid}/{row_id}.{content_type}"
            return f"{DEFAULT_API_PATH}{dataid}.{content_type}"

    raise Exception("This method requires at least a dataset_id or content_type.")


def authentication_validation(username, password, access_token):
    """
    Only accept one form of authentication.
    """
    if bool(username) is not bool(password):
        raise Exception("Basic authentication requires a username AND password.")
    if (username and access_token) or (password and access_token):
        raise Exception(
            "Cannot use both Basic Authentication and"
            " OAuth2.0. Please use only one authentication"
            " method."
        )


def download_file(url, local_filename):
    """
    Utility function that downloads a chunked response from the specified url to a local path.
    This method is suitable for larger downloads.
    """
    response = requests.get(url, stream=True)
    with open(local_filename, "wb") as outfile:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:  # filter out keep-alive new chunks
                outfile.write(chunk)


def format_response(response):
    content_type = response.headers.get("content-type", "").strip().lower()
    if re.match(r"application\/(vnd\.geo\+)?json", content_type):
        return response.json()
    if re.match(r"text\/csv", content_type):
        csv_stream = StringIO(response.text)
        return list(csv.reader(csv_stream))
    if "xml" in content_type:
        return response.content
    if re.match(r"text\/plain", content_type):
        try:
            return json.loads(response.text)
        except ValueError:
            return response.text

    raise RuntimeError(f"Unknown response format: {content_type}")
