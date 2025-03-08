[![PyPI version](https://badge.fury.io/py/sodapy.svg)](http://badge.fury.io/py/sodapy) [![Build Status](https://travis-ci.com/xmunoz/sodapy.svg?branch=master)](https://travis-ci.com/xmunoz/sodapy) [![Code Coverage](https://codecov.io/github/xmunoz/sodapy/coverage.svg?branch=master)](https://codecov.io/github/xmunoz/sodapy)

# sodapy

sodapy is a python client for the [Socrata Open Data API](https://dev.socrata.com/).

## Installation

You can install with `pip install sodapy`.

If you want to install from source, then clone this repository and run `python setup.py install` from the project root.

## Requirements

At its core, this library depends heavily on the [Requests](http://docs.python-requests.org/en/latest/) package. All other requirements can be found in [requirements.txt](https://github.com/xmunoz/sodapy/blob/master/requirements.txt). `sodapy` is currently compatible with Python 3.5, 3.6, 3.7, 3.8, 3.9, and 3.10.

## Documentation

The [official Socrata Open Data API docs](http://dev.socrata.com/) provide thorough documentation of the available methods, as well as [other client libraries](https://dev.socrata.com/libraries/). A quick list of eligible domains to use with this API is available via the [Socrata Discovery API](https://socratadiscovery.docs.apiary.io/#reference/0/count-by-domain/count-by-domain?console=1) or [Socrata's Open Data Network](https://www.opendatanetwork.com/).

This library supports writing directly to datasets with the Socrata Open Data API. For write operations that use data transformations in the Socrata Data Management Experience (the user interface for creating datasets), use the Socrata Data Management API. For more details on when to use SODA vs the Data Management API, see the [Data Management API documentation](https://socratapublishing.docs.apiary.io/#). A Python SDK for the Socrata Data Management API can be found at [socrata-py](https://github.com/socrata/socrata-py).

## Examples

There are some [Jupyter](https://jupyter.org/) notebooks in the [examples directory](examples) with usage examples of sodapy in action.

## Interface

### Table of Contents

- [client](#client)
- [`datasets`](#datasetslimit0-offset0)
- [`get`](#getdataset_identifier-content_typejson-kwargs)
- [`get_all`](#get_alldataset_identifier-content_typejson-kwargs)
- [`get_metadata`](#get_metadatadataset_identifier-content_typejson)
- [`update_metadata`](#update_metadatadataset_identifier-update_fields-content_typejson)
- [`download_attachments`](#download_attachmentsdataset_identifier-content_typejson-download_dirsodapy_downloads)
- [`create`](#createname-kwargs)
- [`publish`](#publishdataset_identifier-content_typejson)
- [`set_permission`](#set_permissiondataset_identifier-permissionprivate-content_typejson)
- [`upsert`](#upsertdataset_identifier-payload-content_typejson)
- [`replace`](#replacedataset_identifier-payload-content_typejson)
- [`create_non_data_file`](#create_non_data_fileparams-file_obj)
- [`replace_non_data_file`](#replace_non_data_filedataset_identifier-params-file_obj)
- [`delete`](#deletedataset_identifier-row_idnone-content_typejson)
- [`close`](#close)

### client

Import the library and set up a connection to get started.

```python
from sodapy import Socrata
client = Socrata(
    "sandbox.demo.socrata.com",
    "FakeAppToken",
    username="fakeuser@somedomain.com",
    password="mypassword",
    timeout=10
)
```

`username` and `password` are only required for creating or modifying data. An application token isn't strictly required (can be `None`), but queries executed from a client without an application token will be subjected to strict throttling limits. You may want to increase the `timeout` seconds when making large requests. To create a bare-bones client:

```python
client = Socrata("sandbox.demo.socrata.com", None)
```

A client can also be created with a context manager to obviate the need for teardown:

```python
with Socrata("sandbox.demo.socrata.com", None) as client:
    # do some stuff
```

The client, by default, makes requests over HTTPS. To modify this behavior, or to make requests through a proxy, take a look [here](https://github.com/xmunoz/sodapy/issues/31#issuecomment-302176628).

### datasets(limit=0, offset=0)

Retrieve datasets associated with a particular domain. The optional `limit` and `offset` keyword args can be used to retrieve a subset of the datasets. By default, all datasets are returned.

    >>> client.datasets()
    [{"resource" : {"name" : "Approved Building Permits", "id" : "msk6-43c6", "parent_fxf" : null, "description" : "Data of approved building/construction permits",...}, {resource : {...}}, ...]

### get(dataset_identifier, content_type="json", \*\*kwargs)

Retrieve data from the requested resources. Filter and query data by field name, id, or using [SoQL keywords](https://dev.socrata.com/docs/queries/).

    >>> client.get("nimj-3ivp", limit=2)
    [{u'geolocation': {u'latitude': u'41.1085', u'needs_recoding': False, u'longitude': u'-117.6135'}, u'version': u'9', u'source': u'nn', u'region': u'Nevada', u'occurred_at': u'2012-09-14T22:38:01', u'number_of_stations': u'15', u'depth': u'7.60', u'magnitude': u'2.7', u'earthquake_id': u'00388610'}, {...}]

    >>> client.get("nimj-3ivp", where="depth > 300", order="magnitude DESC", exclude_system_fields=False)
    [{u'geolocation': {u'latitude': u'-15.563', u'needs_recoding': False, u'longitude': u'-175.6104'}, u'version': u'9', u':updated_at': 1348778988, u'number_of_stations': u'275', u'region': u'Tonga', u':created_meta': u'21484', u'occurred_at': u'2012-09-13T21:16:43', u':id': 132, u'source': u'us', u'depth': u'328.30', u'magnitude': u'4.8', u':meta': u'{\n}', u':updated_meta': u'21484', u'earthquake_id': u'c000cnb5', u':created_at': 1348778988}, {...}]

    >>> client.get("nimj-3ivp/193", exclude_system_fields=False)
    {u'geolocation': {u'latitude': u'21.6711', u'needs_recoding': False, u'longitude': u'142.9236'}, u'version': u'C', u':updated_at': 1348778988, u'number_of_stations': u'136', u'region': u'Mariana Islands region', u':created_meta': u'21484', u'occurred_at': u'2012-09-13T11:19:07', u':id': 193, u'source': u'us', u'depth': u'300.70', u'magnitude': u'4.4', u':meta': u'{\n}', u':updated_meta': u'21484', u':position': 193, u'earthquake_id': u'c000cmsq', u':created_at': 1348778988}

    >>> client.get("nimj-3ivp", region="Kansas")
    [{u'geolocation': {u'latitude': u'38.10', u'needs_recoding': False, u'longitude': u'-100.6135'}, u'version': u'9', u'source': u'nn', u'region': u'Kansas', u'occurred_at': u'2010-09-19T20:52:09', u'number_of_stations': u'15', u'depth': u'300.0', u'magnitude': u'1.9', u'earthquake_id': u'00189621'}, {...}]

### get_all(dataset_identifier, content_type="json", \*\*kwargs)

Read data from the requested resource, paginating over all results. Accepts the same arguments as [`get()`](#getdataset_identifier-content_typejson-kwargs). Returns a generator.

    >>> client.get_all("nimj-3ivp")
    <generator object Socrata.get_all at 0x7fa0dc8be7b0>

    >>> for item in client.get_all("nimj-3ivp"):
    ...     print(item)
    ...
    {'geolocation': {'latitude': '-15.563', 'needs_recoding': False, 'longitude': '-175.6104'}, 'version': '9', ':updated_at': 1348778988, 'number_of_stations': '275', 'region': 'Tonga', ':created_meta': '21484', 'occurred_at': '2012-09-13T21:16:43', ':id': 132, 'source': 'us', 'depth': '328.30', 'magnitude': '4.8', ':meta': '{\n}', ':updated_meta': '21484', 'earthquake_id': 'c000cnb5', ':created_at': 1348778988}
    ...

    >>> import itertools
    >>> items = client.get_all("nimj-3ivp")
    >>> first_five = list(itertools.islice(items, 5))
    >>> len(first_five)
    5

### get_metadata(dataset_identifier, content_type="json")

Retrieve the metadata associated with a particular dataset.

    >>> client.get_metadata("nimj-3ivp")
    {"newBackend": false, "licenseId": "CC0_10", "publicationDate": 1436655117, "viewLastModified": 1451289003, "owner": {"roleName": "administrator", "rights": [], "displayName": "Brett", "id": "cdqe-xcn5", "screenName": "Brett"}, "query": {}, "id": "songs", "createdAt": 1398014181, "category": "Public Safety", "publicationAppendEnabled": true, "publicationStage": "published", "rowsUpdatedBy": "cdqe-xcn5", "publicationGroup": 1552205, "displayType": "table", "state": "normal", "attributionLink": "http://foo.bar.com", "tableId": 3523378, "columns": [], "metadata": {"rdfSubject": "0", "renderTypeConfig": {"visible": {"table": true}}, "availableDisplayTypes": ["table", "fatrow", "page"], "attachments": ... }}

### update_metadata(dataset_identifier, update_fields, content_type="json")

Update the metadata for a particular dataset. `update_fields` should be a dictionary containing only the metadata keys that you wish to overwrite.

Note: Invalid payloads to this method could corrupt the dataset or visualization. See [this comment](https://github.com/xmunoz/sodapy/issues/22#issuecomment-249971379) for more information.

    >>> client.update_metadata("nimj-3ivp", {"attributionLink": "https://anothertest.com"})
    {"newBackend": false, "licenseId": "CC0_10", "publicationDate": 1436655117, "viewLastModified": 1451289003, "owner": {"roleName": "administrator", "rights": [], "displayName": "Brett", "id": "cdqe-xcn5", "screenName": "Brett"}, "query": {}, "id": "songs", "createdAt": 1398014181, "category": "Public Safety", "publicationAppendEnabled": true, "publicationStage": "published", "rowsUpdatedBy": "cdqe-xcn5", "publicationGroup": 1552205, "displayType": "table", "state": "normal", "attributionLink": "https://anothertest.com", "tableId": 3523378, "columns": [], "metadata": {"rdfSubject": "0", "renderTypeConfig": {"visible": {"table": true}}, "availableDisplayTypes": ["table", "fatrow", "page"], "attachments": ... }}

### download_attachments(dataset_identifier, content_type="json", download_dir="~/sodapy_downloads")

Download all attachments associated with a dataset. Return a list of paths to the downloaded files.

    >>> client.download_attachments("nimj-3ivp", download_dir="~/Desktop")
        ['/Users/xmunoz/Desktop/nimj-3ivp/FireIncident_Codes.PDF', '/Users/xmunoz/Desktop/nimj-3ivp/AccidentReport.jpg']

### create(name, \*\*kwargs)

Create a new dataset. Optionally, specify keyword args such as:

- `description` description of the dataset
- `columns` list of fields
- `category` dataset category (must exist in /admin/metadata)
- `tags` list of tag strings
- `row_identifier` field name of primary key
- `new_backend` whether to create the dataset in the new backend

Example usage:

    >>> columns = [{"fieldName": "delegation", "name": "Delegation", "dataTypeName": "text"}, {"fieldName": "members", "name": "Members", "dataTypeName": "number"}]
    >>> tags = ["politics", "geography"]
    >>> client.create("Delegates", description="List of delegates", columns=columns, row_identifier="delegation", tags=tags, category="Transparency")
    {u'id': u'2frc-hyvj', u'name': u'Foo Bar', u'description': u'test dataset', u'publicationStage': u'unpublished', u'columns': [ { u'name': u'Foo', u'dataTypeName': u'text', u'fieldName': u'foo', ... }, { u'name': u'Bar', u'dataTypeName': u'number', u'fieldName': u'bar', ... } ], u'metadata': { u'rowIdentifier': 230641051 }, ... }

### publish(dataset_identifier, content_type="json")

Publish a dataset after creating it, i.e. take it out of 'working copy' mode. The dataset id `id` returned from `create` will be used to publish.

    >>> client.publish("2frc-hyvj")
    {u'id': u'2frc-hyvj', u'name': u'Foo Bar', u'description': u'test dataset', u'publicationStage': u'unpublished', u'columns': [ { u'name': u'Foo', u'dataTypeName': u'text', u'fieldName': u'foo', ... }, { u'name': u'Bar', u'dataTypeName': u'number', u'fieldName': u'bar', ... } ], u'metadata': { u'rowIdentifier': 230641051 }, ... }

### set_permission(dataset_identifier, permission="private", content_type="json")

Set the permissions of a dataset to public or private.

    >>> client.set_permission("2frc-hyvj", "public")
    <Response [200]>

### upsert(dataset_identifier, payload, content_type="json")

Create a new row in an existing dataset.

    >>> data = [{'Delegation': 'AJU', 'Name': 'Alaska', 'Key': 'AL', 'Entity': 'Juneau'}]
    >>> client.upsert("eb9n-hr43", data)
    {u'Errors': 0, u'Rows Deleted': 0, u'Rows Updated': 0, u'By SID': 0, u'Rows Created': 1, u'By RowIdentifier': 0}

Update/Delete rows in a dataset.

    >>> data = [{'Delegation': 'sfa', ':id': 8, 'Name': 'bar', 'Key': 'doo', 'Entity': 'dsfsd'}, {':id': 7, ':deleted': True}]
    >>> client.upsert("eb9n-hr43", data)
    {u'Errors': 0, u'Rows Deleted': 1, u'Rows Updated': 1, u'By SID': 2, u'Rows Created': 0, u'By RowIdentifier': 0}

`upsert`'s can even be performed with a csv file.

    >>> data = open("upsert_test.csv")
    >>> client.upsert("eb9n-hr43", data)
    {u'Errors': 0, u'Rows Deleted': 0, u'Rows Updated': 1, u'By SID': 1, u'Rows Created': 0, u'By RowIdentifier': 0}

### replace(dataset_identifier, payload, content_type="json")

Similar in usage to `upsert`, but overwrites existing data.

    >>> data = open("replace_test.csv")
    >>> client.replace("eb9n-hr43", data)
    {u'Errors': 0, u'Rows Deleted': 0, u'Rows Updated': 0, u'By SID': 0, u'Rows Created': 12, u'By RowIdentifier': 0}

### create_non_data_file(params, file_obj)

Creates a new file-based dataset with the name provided in the files
tuple. A valid file input would be:

```python
files = (
    {'file': ("gtfs2", open('myfile.zip', 'rb'))}
)
```

```python
with open(nondatafile_path, 'rb') as f:
    files = (
        {'file': ("nondatafile.zip", f)}
    )
    response = client.create_non_data_file(params, files)
```

### replace_non_data_file(dataset_identifier, params, file_obj)

Same as create_non_data_file, but replaces a file that already exists in a
file-based dataset.

Note: a table-based dataset cannot be replaced by a file-based dataset. Use create_non_data_file in order to replace.

```python
with open(nondatafile_path, 'rb') as f:
    files = (
        {'file': ("nondatafile.zip", f)}
    )
response = client.replace_non_data_file(DATASET_IDENTIFIER, {}, files)
```

### delete(dataset_identifier, row_id=None, content_type="json")

Delete an individual row.

    >>> client.delete("nimj-3ivp", row_id=2)
    <Response [200]>

Delete the entire dataset.

    >>> client.delete("nimj-3ivp")
    <Response [200]>

### close()

Close the session when you're finished.

```python
client.close()
```

## Run tests

```sh
pytest
```

## Contributing

See [CONTRIBUTING.md](https://github.com/xmunoz/sodapy/blob/master/CONTRIBUTING.md).

## History

This package was initially created and maintained by [**@xmunoz**](https://github.com/xmunoz). On March 8, 2025, ownership was transferred to [**@afeld**](https://github.com/xmunoz).

## Meta

This package uses [semantic versioning](https://semver.org/).

Source and wheel distributions are available on PyPI. Here is how I create those releases.

```sh
python3 setup.py bdist_wheel
python3 setup.py sdist
twine upload dist/*
```
