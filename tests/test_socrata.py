from collections.abc import Generator
import inspect
import json
import logging
import os.path
import requests
import requests_mock
import pytest

from sodapy import Socrata
from sodapy.constants import DEFAULT_API_PATH, DEFAULT_DATASETS_LIMIT, DEFAULT_ROW_LIMIT


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
    with Socrata(REAL_DOMAIN, None) as client:
        yield client


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
    assert len(response) == DEFAULT_ROW_LIMIT


@pytest.mark.vcr
def test_get_csv(real_client):
    response = real_client.get(REAL_DATASET_IDENTIFIER, content_type="csv")
    assert isinstance(response, list)
    # has a header row
    assert len(response) == DEFAULT_ROW_LIMIT + 1


@pytest.mark.vcr
def test_get_xml(real_client):
    response = real_client.get(REAL_DATASET_IDENTIFIER, content_type="xml")
    assert isinstance(response, bytes)


@pytest.mark.vcr
def test_get_missing(real_client):
    with pytest.raises(requests.exceptions.HTTPError):
        real_client.get(FAKE_DATASET_IDENTIFIER)


@pytest.mark.vcr
def test_get_all(real_client):
    response = real_client.get_all(REAL_DATASET_IDENTIFIER)
    assert inspect.isgenerator(response)

    desired_count = DEFAULT_ROW_LIMIT + 1
    list_responses = [item for _, item in zip(range(desired_count), response)]
    assert len(list_responses) == desired_count


@pytest.mark.vcr
def test_get_all_hit_limit(real_client):
    # small dataset
    # https://data.cityofnewyork.us/City-Government/New-York-City-Population-by-Borough-1950-2040/xywu-7bv9/about_data
    response = real_client.get_all("xywu-7bv9")
    assert inspect.isgenerator(response)

    num_elements = sum(1 for _ in response)
    assert num_elements == 6


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
    desired_count = 7
    response = real_client.datasets(limit=desired_count)
    assert isinstance(response, list)
    for dataset in response:
        assert dataset["metadata"]["domain"] == REAL_DOMAIN
    assert len(response) == desired_count


@pytest.mark.vcr
def test_all_datasets(real_client):
    response = real_client.all_datasets(attribution="Department of Transportation (DOT)")
    assert isinstance(response, Generator)

    datasets = list(response)
    num_datasets = len(datasets)
    assert num_datasets > DEFAULT_DATASETS_LIMIT

    ids = [dataset["resource"]["id"] for dataset in datasets]
    # https://stackoverflow.com/questions/5278122/checking-if-all-elements-in-a-list-are-unique
    assert num_datasets == len(set(ids)), "IDs should be unique"


@pytest.mark.vcr
def test_get_datasets_bad_domain():
    client = Socrata("not-socrata.com", None)

    with pytest.raises(requests.exceptions.ConnectionError):
        client.datasets()

    client.close()


@pytest.mark.vcr
def test_get_metadata(real_client):
    metadata = real_client.get_metadata(REAL_DATASET_IDENTIFIER)

    assert isinstance(metadata, dict)
    resource = metadata["resource"]
    assert resource["name"] == "Bicycle Counts"
    assert resource["attribution"] == "Department of Transportation (DOT)"


@pytest.mark.vcr
def test_get_metadata_missing(real_client):
    with pytest.raises(requests.exceptions.HTTPError):
        real_client.get_metadata(FAKE_DATASET_IDENTIFIER)


@pytest.mark.vcr
def test_download_attachments(real_client):
    response = real_client.download_attachments(REAL_DATASET_IDENTIFIER)

    assert isinstance(response, list)
    assert len(response) == 1
    assert response[0].endswith(".xlsx")


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
