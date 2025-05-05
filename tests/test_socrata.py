from collections.abc import Generator
import inspect
import json
import logging
import os.path
from pathlib import Path
import requests
import requests_mock
import pytest

from sodapy import Socrata
from sodapy.constants import DEFAULT_DATASETS_LIMIT, DEFAULT_ROW_LIMIT


FAKE_DOMAIN = "fakedomain.com"
FAKE_DATASET_IDENTIFIER = "songs"
REAL_DOMAIN = "data.cityofnewyork.us"
# https://data.cityofnewyork.us/Transportation/Bicycle-Counts/uczf-rk3c/about_data
REAL_DATASET_IDENTIFIER = "uczf-rk3c"

APPTOKEN = "FakeAppToken"
TEST_DATA_PATH = Path(os.path.dirname(__file__)) / "test_data"
LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def vcr_config():
    # https://vcrpy.readthedocs.io/en/latest/usage.html#record-modes
    return {"record_mode": "new_episodes"}


@pytest.fixture
def real_client():
    with Socrata(REAL_DOMAIN) as client:
        yield client


def test_client():
    client = Socrata(FAKE_DOMAIN, APPTOKEN)
    assert isinstance(client, Socrata)
    client.close()


def test_client_warning(caplog):
    with caplog.at_level(logging.WARNING):
        client = Socrata(FAKE_DOMAIN)
    assert "strict throttling limits" in caplog.text
    client.close()


def test_context_manager():
    with Socrata(FAKE_DOMAIN, APPTOKEN) as client:
        assert isinstance(client, Socrata)


def test_context_manager_no_domain_exception():
    with pytest.raises(Exception):
        with Socrata(None, APPTOKEN):  # type: ignore
            pass


def test_context_manager_timeout_exception():
    with pytest.raises(TypeError):
        with Socrata(FAKE_DOMAIN, APPTOKEN, timeout="fail"):  # type: ignore
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
    client = Socrata(FAKE_DOMAIN, APPTOKEN)

    with open(TEST_DATA_PATH / "get_songs_unicode.json") as f:
        response_data = json.load(f)

    with requests_mock.Mocker() as m:
        m.get(
            f"https://{FAKE_DOMAIN}/resource/songs.json",
            headers={"Content-Type": "application/json"},
            json=response_data,
        )

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
    client = Socrata("not-socrata.com")

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
