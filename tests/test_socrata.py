import inspect
import json
import logging
import os.path
import requests
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
USERNAME = "fakeuser"
PASSWORD = "fakepassword"

TEST_DATA_PATH = os.path.join(os.path.dirname(__file__), "test_data")
LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def vcr_config():
    # https://vcrpy.readthedocs.io/en/latest/usage.html#record-modes
    return {"record_mode": "new_episodes"}


@pytest.fixture
def real_client():
    client = Socrata(REAL_DOMAIN, None)
    yield client
    client.close()


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


@pytest.mark.vcr
def test_get_csv(real_client):
    response = real_client.get(REAL_DATASET_IDENTIFIER, content_type="csv")
    assert isinstance(response, list)
    # has a header row
    assert len(response) == real_client.DEFAULT_LIMIT + 1


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

    desired_count = real_client.DEFAULT_LIMIT + 1
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
    response = real_client.datasets(limit=7)
    assert isinstance(response, list)
    assert len(response) == 7


@pytest.mark.vcr
def test_get_datasets_bad_domain():
    client = Socrata("not-socrata.com", None)

    with pytest.raises(requests.exceptions.ConnectionError):
        client.datasets()

    client.close()


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


@pytest.mark.vcr
def test_get_metadata_and_attachments_missing(real_client):
    with pytest.raises(requests.exceptions.HTTPError):
        real_client.get_metadata(FAKE_DATASET_IDENTIFIER)


def test_update_metadata():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(FAKE_DOMAIN, APPTOKEN, session_adapter=mock_adapter)

    response_data = "update_song_metadata.txt"
    setup_old_api_mock(adapter, "PUT", response_data, 200)
    data = {"category": "Education", "attributionLink": "https://testing.updates"}

    response = client.update_metadata(FAKE_DATASET_IDENTIFIER, data)

    assert isinstance(response, dict)
    assert response.get("category") == data["category"]
    assert response.get("attributionLink") == data["attributionLink"]

    client.close()


def test_upsert_exception():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(FAKE_DOMAIN, APPTOKEN, session_adapter=mock_adapter)

    response_data = "403_response_json.txt"
    setup_mock(adapter, "POST", response_data, 403, reason="Forbidden")

    data = [
        {
            "theme": "Surfing",
            "artist": "Wavves",
            "title": "King of the Beach",
            "year": "2010",
        }
    ]
    try:
        client.upsert(FAKE_DATASET_IDENTIFIER, data)
    except Exception as e:
        assert isinstance(e, requests.exceptions.HTTPError)
    else:
        raise AssertionError("No exception raised for bad request.")


def test_upsert():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(
        FAKE_DOMAIN,
        APPTOKEN,
        username=USERNAME,
        password=PASSWORD,
        session_adapter=mock_adapter,
    )

    response_data = "upsert_songs.txt"
    data = [
        {
            "theme": "Surfing",
            "artist": "Wavves",
            "title": "King of the Beach",
            "year": "2010",
        }
    ]
    setup_mock(adapter, "POST", response_data, 200)
    response = client.upsert(FAKE_DATASET_IDENTIFIER, data)

    assert isinstance(response, dict)
    assert response.get("Rows Created") == 1
    client.close()


def test_replace():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(
        FAKE_DOMAIN,
        APPTOKEN,
        username=USERNAME,
        password=PASSWORD,
        session_adapter=mock_adapter,
    )

    response_data = "replace_songs.txt"
    data = [
        {
            "theme": "Surfing",
            "artist": "Wavves",
            "title": "King of the Beach",
            "year": "2010",
        },
        {
            "theme": "History",
            "artist": "Best Friends Forever",
            "title": "Abe Lincoln",
            "year": "2008",
        },
    ]
    setup_mock(adapter, "PUT", response_data, 200)
    response = client.replace(FAKE_DATASET_IDENTIFIER, data)

    assert isinstance(response, dict)
    assert response.get("Rows Created") == 2
    client.close()


def test_delete():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(
        FAKE_DOMAIN,
        APPTOKEN,
        username=USERNAME,
        password=PASSWORD,
        session_adapter=mock_adapter,
    )

    uri = "{}{}{}/{}.json".format(PREFIX, FAKE_DOMAIN, OLD_API_PATH, FAKE_DATASET_IDENTIFIER)
    adapter.register_uri("DELETE", uri, status_code=200)
    response = client.delete(FAKE_DATASET_IDENTIFIER)
    assert response.status_code == 200

    try:
        client.delete("foobar")
    except Exception as e:
        assert isinstance(e, requests_mock.exceptions.NoMockAddress)
    finally:
        client.close()


def test_create():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(
        FAKE_DOMAIN,
        APPTOKEN,
        username=USERNAME,
        password=PASSWORD,
        session_adapter=mock_adapter,
    )

    response_data = "create_foobar.txt"
    setup_mock(adapter, "POST", response_data, 200, dataset_identifier=None)

    columns = [
        {"fieldName": "foo", "name": "Foo", "dataTypeName": "text"},
        {"fieldName": "bar", "name": "Bar", "dataTypeName": "number"},
    ]
    tags = ["foo", "bar"]
    response = client.create(
        "Foo Bar",
        description="test dataset",
        columns=columns,
        tags=tags,
        row_identifier="bar",
    )

    request = adapter.request_history[0]
    request_payload = json.loads(request.text)  # can't figure out how to use .json

    # Test request payload
    for dataset_key in ["name", "description", "columns", "tags"]:
        assert dataset_key in request_payload

    for column_key in ["fieldName", "name", "dataTypeName"]:
        assert column_key in request_payload["columns"][0]

    # Test response
    assert isinstance(response, dict)
    assert len(response.get("id")) == 9
    client.close()


def test_set_permission():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(
        FAKE_DOMAIN,
        APPTOKEN,
        username=USERNAME,
        password=PASSWORD,
        session_adapter=mock_adapter,
    )

    response_data = "empty.txt"
    setup_old_api_mock(adapter, "PUT", response_data, 200)

    # Test response
    response = client.set_permission(FAKE_DATASET_IDENTIFIER, "public")
    assert response.status_code == 200

    # Test request
    request = adapter.request_history[0]
    query_string = request.url.split("?")[-1]
    params = query_string.split("&")

    assert len(params) == 2
    assert "method=setPermission" in params
    assert "value=public.read" in params

    client.close()


def test_publish():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(
        FAKE_DOMAIN,
        APPTOKEN,
        username=USERNAME,
        password=PASSWORD,
        session_adapter=mock_adapter,
    )

    response_data = "create_foobar.txt"
    setup_publish_mock(adapter, "POST", response_data, 200)

    response = client.publish(FAKE_DATASET_IDENTIFIER)
    assert isinstance(response, dict)
    assert len(response.get("id")) == 9
    client.close()


def test_import_non_data_file():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(
        FAKE_DOMAIN,
        APPTOKEN,
        username=USERNAME,
        password=PASSWORD,
        session_adapter=mock_adapter,
    )

    response_data = "successblobres.txt"
    nondatasetfile_path = "tests/test_data/nondatasetfile.zip"

    setup_import_non_data_file(adapter, "POST", response_data, 200)

    with open(nondatasetfile_path, "rb") as f:
        files = {"file": ("nondatasetfile.zip", f)}
        response = client.create_non_data_file({}, files)

    assert isinstance(response, dict)
    assert response.get("blobFileSize") == 496
    client.close()


def test_replace_non_data_file():
    mock_adapter = {}
    mock_adapter["prefix"] = PREFIX
    adapter = requests_mock.Adapter()
    mock_adapter["adapter"] = adapter
    client = Socrata(
        FAKE_DOMAIN,
        APPTOKEN,
        username=USERNAME,
        password=PASSWORD,
        session_adapter=mock_adapter,
    )

    response_data = "successblobres.txt"
    nondatasetfile_path = "tests/test_data/nondatasetfile.zip"

    setup_replace_non_data_file(adapter, "POST", response_data, 200)

    with open(nondatasetfile_path, "rb") as fin:
        file = {"file": ("nondatasetfile.zip", fin)}
        response = client.replace_non_data_file(FAKE_DATASET_IDENTIFIER, {}, file)

    assert isinstance(response, dict)
    assert response.get("blobFileSize") == 496
    client.close()


def setup_publish_mock(
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
        body = json.load(response_body)

    uri = "{}{}{}/{}/publication.{}".format(
        PREFIX, FAKE_DOMAIN, OLD_API_PATH, dataset_identifier, content_type
    )

    headers = {"content-type": "application/json; charset=utf-8"}

    adapter.register_uri(
        method,
        uri,
        status_code=response_code,
        json=body,
        reason=reason,
        headers=headers,
    )


def setup_import_non_data_file(
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
        body = json.load(response_body)

    uri = "{}{}/api/imports2/?method=blob".format(PREFIX, FAKE_DOMAIN)

    headers = {"content-type": "application/json; charset=utf-8"}

    adapter.register_uri(
        method,
        uri,
        status_code=response_code,
        json=body,
        reason=reason,
        headers=headers,
    )


def setup_replace_non_data_file(
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
        body = json.load(response_body)

    uri = "{}{}{}/{}.{}?method=replaceBlob&id={}".format(
        PREFIX,
        FAKE_DOMAIN,
        OLD_API_PATH,
        dataset_identifier,
        "txt",
        dataset_identifier,
    )

    headers = {"content-type": "text/plain; charset=utf-8"}

    adapter.register_uri(
        method,
        uri,
        status_code=response_code,
        json=body,
        reason=reason,
        headers=headers,
    )


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
