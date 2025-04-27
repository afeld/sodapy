import requests

from .constants import DEFAULT_API_PATH, OLD_API_PATH


# Utility methods
def raise_for_status(response):
    """
    Custom raise_for_status with more appropriate error message.
    """
    http_error_msg = ""

    if 400 <= response.status_code < 500:
        http_error_msg = "{} Client Error: {}".format(
            response.status_code, response.reason
        )

    elif 500 <= response.status_code < 600:
        http_error_msg = "{} Server Error: {}".format(
            response.status_code, response.reason
        )

    if http_error_msg:
        try:
            more_info = response.json().get("message")
        except ValueError:
            more_info = None
        if more_info and more_info.lower() != response.reason.lower():
            http_error_msg += ".\n\t{}".format(more_info)
        raise requests.exceptions.HTTPError(http_error_msg, response=response)


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
            return "{}/{}.{}".format(OLD_API_PATH, dataid, content_type)
        return "{}/{}".format(OLD_API_PATH, dataid)

    if content_type is not None:
        return "{}.{}".format(OLD_API_PATH, content_type)

    raise Exception("This method requires at least a dataset_id or content_type.")


def format_new_api_request(dataid=None, row_id=None, content_type=None):
    if dataid is not None:
        if content_type is not None:
            if row_id is not None:
                return "{}{}/{}.{}".format(
                    DEFAULT_API_PATH, dataid, row_id, content_type
                )
            return "{}{}.{}".format(DEFAULT_API_PATH, dataid, content_type)

    raise Exception("This method requires at least a dataset_id or content_type.")


def authentication_validation(username, password, access_token):
    """
    Only accept one form of authentication.
    """
    if bool(username) is not bool(password):
        raise Exception("Basic authentication requires a username AND" " password.")
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
