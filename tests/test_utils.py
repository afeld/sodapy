import pytest
import requests
import requests_mock
import sodapy.utils as utils


@pytest.mark.parametrize(
    ("status_code", "status_type", "reason", "raises_exception"),
    [
        (200, "Success", "OK", False),
        (300, "Redirection", "Multiple Choices", False),
        (400, "Client Error", "Bad Request", True),
        (500, "Server Error", "Internal Server Error", True),
        (600, "Foo Bar", "Here be dragons", False),
    ],
)
def test_raise_for_status(status_code, status_type, reason, raises_exception):
    response = requests.models.Response()
    response.status_code = status_code
    response.reason = reason

    if raises_exception:
        with pytest.raises(
            requests.exceptions.HTTPError,
            match="{} {}: {}".format(status_code, status_type, reason),
        ):
            utils.raise_for_status(response)
    else:
        utils.raise_for_status(response)


@pytest.mark.parametrize(
    ("elems", "result"),
    [
        ({}, {}),
        ({"a": 1, "b": None, "c": "d"}, {"a": 1, "c": "d"}),
        ({"s": "", "c": 0}, {"s": "", "c": 0}),
    ],
)
def test_clear_empty_values(elems, result):
    assert utils.clear_empty_values(elems) == result


def test_format_old_api_request_exception():
    with pytest.raises(Exception):
        utils.format_old_api_request()


@pytest.mark.parametrize(
    ("dataid", "content_type", "path"),
    [
        ("abcd", None, "/api/views/abcd"),
        ("abcd", "json", "/api/views/abcd.json"),
        (None, "json", "/api/views.json"),
    ],
)
def test_format_old_api_request(dataid, content_type, path):
    assert utils.format_old_api_request(dataid=dataid, content_type=content_type) == path


@pytest.mark.parametrize(
    ("dataid", "row_id", "content_type", "path"),
    [
        ("abcd", None, "json", "/resource/abcd.json"),
        ("abcd", 123, "json", "/resource/abcd/123.json"),
    ],
)
def test_format_new_api_request(dataid, row_id, content_type, path):
    assert (
        utils.format_new_api_request(dataid=dataid, row_id=row_id, content_type=content_type)
        == path
    )


def test_format_new_api_request_exception():
    with pytest.raises(Exception):
        utils.format_new_api_request()


@pytest.mark.parametrize(
    ("username", "password", "token"),
    [("me", None, "123456"), (None, "pass", "123456"), ("me", "pass", "123456")],
)
def test_authentication_validation_exceptions(username, password, token):
    with pytest.raises(Exception):
        utils.authentication_validation(username, password, token)


@pytest.mark.parametrize(
    ("username", "password", "token"),
    [("me", "pass", None), (None, None, "93738")],
)
def test_authentication_validation(username, password, token):
    utils.authentication_validation(username, password, token)


def test_download_file(tmp_path):
    path = tmp_path / "myfile.txt"
    url = "http://fileserver.dev/file"
    text = "the response data"
    with requests_mock.Mocker() as mock:
        mock.get(url, text=text)
        utils.download_file(url, str(path))
    assert path.read_text() == text
