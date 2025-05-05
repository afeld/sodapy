import logging
import os
from pathlib import Path
from urllib.parse import urlencode


# use Union instead of `|`s for Python 3.9 compatability
from typing import Any, Union

import requests

from sodapy.constants import (
    DATASETS_PATH,
    DEFAULT_DATASETS_LIMIT,
    DEFAULT_OFFSET,
    DEFAULT_ROW_LIMIT,
)
from sodapy import utils


class Sodapy:
    """
    The main class that interacts with the SODA API. Sample usage:
        from sodapy import Sodapy
        client = Sodapy("some.portal.gov")
    """

    def __init__(
        self,
        domain: str,
        app_token: Union[str, None] = None,
        username: Union[str, None] = None,
        password: Union[str, None] = None,
        access_token: Union[str, None] = None,
        timeout: Union[int, float] = 10,
    ):
        """
        The required arguments are:
            domain: the domain you wish you to access
        Simple requests are possible without an app_token, though these
        requests will be rate-limited.

        For private datasets, the Socrata API currently supports basic HTTP authentication, which requires these additional parameters.
            username: your Socrata username
            password: your Socrata password

        The basic HTTP authentication comes with a deprecation warning, and the
        current recommended authentication method is OAuth 2.0. To make
        requests on behalf of the user using OAuth 2.0 authentication, follow
        the recommended procedure and provide the final access_token to the
        client.

        More information about authentication can be found in the official
        docs:
            http://dev.socrata.com/docs/authentication.html
        """
        self.domain = domain

        # set up the session with proper authentication crendentials
        self.session = requests.Session()
        if not app_token:
            logging.warning(
                "Requests made without an app_token will be subject to strict throttling limits."
            )
        else:
            self.session.headers.update({"X-App-token": app_token})

        utils.authentication_validation(username, password, access_token)

        # use either basic HTTP auth or OAuth2.0
        if username and password:
            self.session.auth = (username, password)
        elif access_token:
            self.session.headers.update({"Authorization": f"OAuth {access_token}"})

        if not isinstance(timeout, (int, float)):
            raise TypeError("Timeout must be numeric.")
        self.timeout = timeout

    def __enter__(self):
        """
        This runs as the with block is set up.
        """
        return self

    def __exit__(self, _exc_type=None, _exc_value=None, _traceback=None):
        """
        This runs at the end of a with block. It simply closes the client.

        Exceptions are propagated forward in the program as usual, and
            are not handled here.
        """
        self.close()

    def datasets(self, **kwargs):
        """Returns the list of datasets associated with a particular domain. [API documentation.](https://dev.socrata.com/docs/other/discovery)"""

        params = {key: utils.format_param(value) for key, value in kwargs.items()}

        # strange behavior: calling the Discovery API under a particular domain without the `domains` parameter returns results from all domains
        params["domains"] = params.get("domains", [self.domain])

        response = self._perform_request(DATASETS_PATH, params=params)
        results: list[dict[str, Any]] = response["results"]  # type: ignore
        return results

    def all_datasets(self, **kwargs):
        """Returns the datasets associated with a particular domain as a Generator. [API documentation.](https://dev.socrata.com/docs/other/discovery) Note that the `limit` is treated as the page size, not a limit on the number of items that are yielded."""

        if "offset" not in kwargs:
            kwargs["offset"] = DEFAULT_OFFSET
        limit = kwargs.get("limit", DEFAULT_DATASETS_LIMIT)

        while True:
            results = self.datasets(**kwargs)
            for item in results:
                yield item

            if len(results) < limit:
                return

            kwargs["offset"] += limit

    def get_metadata(self, dataset_identifier: str):
        """
        Retrieve the metadata for a particular dataset. While there is a [Metadata API](https://dev.socrata.com/docs/other/metadata.html), this uses the [Discovery API](https://dev.socrata.com/docs/other/discovery#?route=get-/catalog/v1-ids--4x4-), as that returns more information.
        """
        response = self.datasets(ids=[dataset_identifier])
        return response[0]

    def _download_url(self, dataset_identifier: str, attachment: dict[str, str]):
        params = {"download": "true"}

        if "assetId" in attachment:
            base = utils.format_old_api_request(dataid=dataset_identifier)
            assetid = attachment["assetId"]
            filename = attachment["filename"]
            params["filename"] = filename
            resource = f"{base}/files/{assetid}"
        else:
            assetid = attachment["blobId"]
            resource = f"/api/assets/{assetid}"

        return f"https://{self.domain}{resource}?{urlencode(params)}"

    def download_attachments(
        self,
        dataset_identifier: str,
        download_dir="~/sodapy_downloads",
    ):
        """
        Download all of the attachments associated with a dataset. Return the paths of downloaded
        files.
        """

        resource = utils.format_old_api_request(dataid=dataset_identifier, content_type="json")
        metadata = self._perform_request(resource)

        files: list[str] = []
        attachments: list[dict[str, Any]] = metadata["metadata"].get("attachments", [])  # type: ignore
        if not attachments:
            logging.info("No attachments were found or downloaded.")
            return files

        download_dir = os.path.join(os.path.expanduser(download_dir), dataset_identifier)
        if not os.path.exists(download_dir):
            os.makedirs(download_dir)

        for attachment in attachments:
            uri = self._download_url(dataset_identifier, attachment)
            file_path = Path(download_dir) / attachment["filename"]
            utils.download_file(uri, file_path)
            files.append(str(file_path))

        logging.info("The following files were downloaded:\n\t%s", "\n\t".join(files))
        return files

    def get(self, dataset_identifier: str, content_type: utils.ContentTypes = "json", **kwargs):
        """
        Read data from the requested resource. Options for content_type are json,
        csv, and xml. Optionally, specify a keyword arg to filter results:

            select : the set of columns to be returned, defaults to *
            where : filters the rows to be returned, defaults to limit
            order : specifies the order of results
            group : column to group results on
            limit : max number of results to return, defaults to 1000
            offset : offset, used for paging. Defaults to 0
            q : performs a full text search for a value
            query : full SoQL query string, all as one parameter
            exclude_system_fields : defaults to true. If set to false, the
                response will include system fields (:id, :created_at, and
                :updated_at)

        More information about the SoQL parameters can be found at the official
        docs:
            http://dev.socrata.com/docs/queries.html

        More information about system fields can be found here:
            http://dev.socrata.com/docs/system-fields.html
        """
        resource = utils.format_new_api_request(
            dataid=dataset_identifier, content_type=content_type
        )
        headers = utils.clear_empty_values({"Accept": kwargs.pop("format", None)})

        # SoQL parameters
        params = {
            "$select": kwargs.pop("select", None),
            "$where": kwargs.pop("where", None),
            "$order": kwargs.pop("order", None),
            "$group": kwargs.pop("group", None),
            "$limit": kwargs.pop("limit", None),
            "$offset": kwargs.pop("offset", None),
            "$q": kwargs.pop("q", None),
            "$query": kwargs.pop("query", None),
            "$$exclude_system_fields": kwargs.pop("exclude_system_fields", None),
        }

        # Additional parameters, such as field names
        params.update(kwargs)
        params = utils.clear_empty_values(params)

        response = self._perform_request(resource, headers=headers, params=params)
        return response

    def get_all(self, *args, **kwargs):
        """
        Read data from the requested resource, paginating over all results.
        Accepts the same arguments as get(). Returns a generator.

        Note that the `limit` is treated as the page size, not a limit on the number of items that are yielded.
        """

        if "offset" not in kwargs:
            kwargs["offset"] = DEFAULT_OFFSET
        limit = kwargs.get("limit", DEFAULT_ROW_LIMIT)

        while True:
            response = self.get(*args, **kwargs)
            for item in response:
                yield item

            if len(response) < limit:
                return
            kwargs["offset"] += limit

    def _perform_request(self, resource: str, **kwargs):
        """
        Utility method that performs GET requests.
        """

        uri = f"https://{self.domain}{resource}"

        response = self.session.get(uri, timeout=self.timeout, **kwargs)
        utils.raise_for_status(response)

        # for other request types, return most useful data
        return utils.format_response(response)

    def close(self):
        """
        Close the session.
        """
        self.session.close()
