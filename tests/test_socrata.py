import inspect
import json
import logging
import os.path
import requests_mock
import pytest

from sodapy import Socrata
from sodapy.constants import DEFAULT_API_PATH, OLD_API_PATH, DATASETS_PATH


PREFIX = "https://"
DOMAIN = "fakedomain.com"
DATASET_IDENTIFIER = "songs"
APPTOKEN = "FakeAppToken"
TEST_DATA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))),
    "test_data",
)
LOGGER = logging.getLogger(__name__)


def test_client():
    client = Socrata(DOMAIN, APPTOKEN)
    assert isinstance(client, Socrata)
    client.close()


def test_client_warning(caplog):
    with caplog.at_level(logging.WARNING):
        client = Socrata(DOMAIN, None)
    assert "strict throttling limits" in caplog.text
    client.close()


def test_context_manager():
    with Socrata(DOMAIN, APPTOKEN) as client:
        assert isinstance(client, Socrata)


def test_context_manager_no_domain_exception():
    with pytest.raises(Exception):
        with Socrata(None, APPTOKEN):
            pass


def test_context_manager_timeout_exception():
    with pytest.raises(TypeError):
        with Socrata(DOMAIN, APPTOKEN, timeout="fail"):
            pass


def test_client_oauth():
    client = Socrata(DOMAIN, APPTOKEN, access_token="AAAAAAAAAAAA")
    assert client.session.headers.get("Authorization") == "OAuth AAAAAAAAAAAA"


def test_get():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(DOMAIN, APPTOKEN, session_adapter=mock_adapter)

    response_data = "get_songs.txt"
    setup_mock(adapter, "GET", response_data, 200)
    response = client.get(DATASET_IDENTIFIER)

    assert isinstance(response, list)
    assert len(response) == 10

    client.close()


def test_get_all():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(DOMAIN, APPTOKEN, session_adapter=mock_adapter)

    setup_mock(adapter, "GET", "bike_counts_page_1.json", 200, query="$offset=0")
    setup_mock(adapter, "GET", "bike_counts_page_2.json", 200, query="$offset=1000")
    response = client.get_all(DATASET_IDENTIFIER)

    assert inspect.isgenerator(response)
    data = list(response)
    assert len(data) == 1001
    assert data[0]["date"] == "2016-09-21T15:45:00.000"
    assert data[-1]["date"] == "2016-10-02T01:45:00.000"

    client.close()


def test_get_unicode():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(DOMAIN, APPTOKEN, session_adapter=mock_adapter)

    response_data = "get_songs_unicode.txt"
    setup_mock(adapter, "GET", response_data, 200)

    response = client.get(DATASET_IDENTIFIER)

    assert isinstance(response, list)
    assert len(response) == 10

    client.close()


def test_get_datasets():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(DOMAIN, APPTOKEN, session_adapter=mock_adapter)

    setup_datasets_mock(adapter, "get_datasets.txt", 200, params={"limit": "7"})
    response = client.datasets(limit=7)

    assert isinstance(response, list)
    assert len(response) == 7


def test_get_metadata_and_attachments():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(DOMAIN, APPTOKEN, session_adapter=mock_adapter)

    response_data = "get_song_metadata.txt"
    setup_old_api_mock(adapter, "GET", response_data, 200)
    response = client.get_metadata(DATASET_IDENTIFIER)

    assert isinstance(response, dict)
    assert "newBackend" in response
    assert "attachments" in response["metadata"]

    response = client.download_attachments(DATASET_IDENTIFIER)

    assert isinstance(response, list)
    assert len(response) == 0

    client.close()


def setup_old_api_mock(
    adapter,
    method,
    response,
    response_code,
    reason="OK",
    dataset_identifier=DATASET_IDENTIFIER,
    content_type="json",
):
    path = os.path.join(TEST_DATA_PATH, response)
    with open(path, "r") as response_body:
        try:
            body = json.load(response_body)
        except ValueError:
            body = None

    uri = "{}{}{}/{}.{}".format(PREFIX, DOMAIN, OLD_API_PATH, dataset_identifier, content_type)

    headers = {"content-type": "application/json; charset=utf-8"}

    adapter.register_uri(
        method,
        uri,
        status_code=response_code,
        json=body,
        reason=reason,
        headers=headers,
    )


def setup_datasets_mock(adapter, response, response_code, reason="OK", params={}):
    path = os.path.join(TEST_DATA_PATH, response)
    with open(path, "r") as response_body:
        body = json.load(response_body)

    uri = "{}{}{}".format(PREFIX, DOMAIN, DATASETS_PATH)

    if "offset" not in params:
        params["offset"] = 0
        uri = "{}?{}".format(uri, "&".join(["{}={}".format(k, v) for k, v in params.items()]))

    headers = {"content-type": "application/json; charset=utf-8"}
    adapter.register_uri(
        "get", uri, status_code=response_code, json=body, reason=reason, headers=headers
    )


def setup_mock(
    adapter,
    method,
    response,
    response_code,
    reason="OK",
    dataset_identifier=DATASET_IDENTIFIER,
    content_type="json",
    query=None,
):
    path = os.path.join(TEST_DATA_PATH, response)
    with open(path, "r") as response_body:
        body = json.load(response_body)

    if dataset_identifier is None:  # for create endpoint
        uri = "{}{}{}.{}".format(PREFIX, DOMAIN, OLD_API_PATH, "json")
    else:  # most cases
        uri = "{}{}{}{}.{}".format(
            PREFIX, DOMAIN, DEFAULT_API_PATH, dataset_identifier, content_type
        )

    if query:
        uri += "?" + query

    headers = {"content-type": "application/json; charset=utf-8"}
    adapter.register_uri(
        method,
        uri,
        status_code=response_code,
        json=body,
        reason=reason,
        headers=headers,
        complete_qs=True,
    )
