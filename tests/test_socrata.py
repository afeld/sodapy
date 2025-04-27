import inspect
import json
import logging
import os.path
import requests_mock
import pytest

from sodapy import Socrata
from sodapy.constants import DEFAULT_API_PATH, OLD_API_PATH


PREFIX = "https://"
FAKE_DOMAIN = "fakedomain.com"
FAKE_DATASET_IDENTIFIER = "songs"
REAL_DOMAIN = "data.cityofnewyork.us"
# https://data.cityofnewyork.us/Transportation/Bicycle-Counts/uczf-rk3c/about_data
REAL_DATASET_IDENTIFIER = "uczf-rk3c"

APPTOKEN = "FakeAppToken"
TEST_DATA_PATH = os.path.join(os.path.dirname(__file__), "test_data")
LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def vcr_config():
    # https://vcrpy.readthedocs.io/en/latest/usage.html#record-modes
    return {"record_mode": "new_episodes"}


@pytest.fixture
def real_client():
    return Socrata(REAL_DOMAIN, None)


def test_client():
    client = Socrata(FAKE_DOMAIN, APPTOKEN)
    assert isinstance(client, Socrata)
    client.close()


def test_client_warning(caplog):
    with caplog.at_level(logging.WARNING):
        client = Socrata(FAKE_DOMAIN, None)
    assert "strict throttling limits" in caplog.text
    client.close()


def test_context_manager():
    with Socrata(FAKE_DOMAIN, APPTOKEN) as client:
        assert isinstance(client, Socrata)


def test_context_manager_no_domain_exception():
    with pytest.raises(Exception):
        with Socrata(None, APPTOKEN):
            pass


def test_context_manager_timeout_exception():
    with pytest.raises(TypeError):
        with Socrata(FAKE_DOMAIN, APPTOKEN, timeout="fail"):
            pass


def test_client_oauth():
    client = Socrata(FAKE_DOMAIN, APPTOKEN, access_token="AAAAAAAAAAAA")
    assert client.session.headers.get("Authorization") == "OAuth AAAAAAAAAAAA"


@pytest.mark.vcr
def test_get(real_client):
    response = real_client.get(REAL_DATASET_IDENTIFIER)
    assert isinstance(response, list)
    assert len(response) == real_client.DEFAULT_LIMIT

    real_client.close()


@pytest.mark.vcr
def test_get_all(real_client):
    response = real_client.get_all(REAL_DATASET_IDENTIFIER)
    assert inspect.isgenerator(response)

    desired_count = real_client.DEFAULT_LIMIT + 1
    list_responses = [item for _, item in zip(range(desired_count), response)]
    assert len(list_responses) == desired_count

    real_client.close()


def test_get_unicode():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(FAKE_DOMAIN, APPTOKEN, session_adapter=mock_adapter)

    response_data = "get_songs_unicode.txt"
    setup_mock(adapter, "GET", response_data, 200)

    response = client.get(FAKE_DATASET_IDENTIFIER)

    assert isinstance(response, list)
    assert len(response) == 10

    client.close()


@pytest.mark.vcr
def test_get_datasets(real_client):
    response = real_client.datasets(limit=7)
    assert isinstance(response, list)
    assert len(response) == 7


@pytest.mark.vcr
def test_get_metadata_and_attachments(real_client):
    response = real_client.get_metadata(REAL_DATASET_IDENTIFIER)

    assert isinstance(response, dict)
    assert response["newBackend"]
    assert response["name"] == "Bicycle Counts"
    assert response["attribution"] == "Department of Transportation (DOT)"

    expected_attachments = 1
    attachments = response["metadata"]["attachments"]
    assert len(attachments) == expected_attachments
    filename = attachments[0]["filename"]

    response = real_client.download_attachments(REAL_DATASET_IDENTIFIER)

    assert isinstance(response, list)
    assert len(response) == expected_attachments
    assert response[0].endswith(f"/{REAL_DATASET_IDENTIFIER}/{filename}")

    real_client.close()


def setup_old_api_mock(
    adapter,
    method,
    response,
    response_code,
    reason="OK",
    dataset_identifier=FAKE_DATASET_IDENTIFIER,
    content_type="json",
):
    path = os.path.join(TEST_DATA_PATH, response)
    with open(path, "r") as response_body:
        try:
            body = json.load(response_body)
        except ValueError:
            body = None

    uri = "{}{}{}/{}.{}".format(PREFIX, FAKE_DOMAIN, OLD_API_PATH, dataset_identifier, content_type)

    headers = {"content-type": "application/json; charset=utf-8"}

    adapter.register_uri(
        method,
        uri,
        status_code=response_code,
        json=body,
        reason=reason,
        headers=headers,
    )


def setup_mock(
    adapter,
    method,
    response,
    response_code,
    reason="OK",
    dataset_identifier=FAKE_DATASET_IDENTIFIER,
    content_type="json",
    query=None,
):
    path = os.path.join(TEST_DATA_PATH, response)
    with open(path, "r") as response_body:
        body = json.load(response_body)

    if dataset_identifier is None:  # for create endpoint
        uri = "{}{}{}.{}".format(PREFIX, FAKE_DOMAIN, OLD_API_PATH, "json")
    else:  # most cases
        uri = "{}{}{}{}.{}".format(
            PREFIX, FAKE_DOMAIN, DEFAULT_API_PATH, dataset_identifier, content_type
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
