[![PyPI version](https://badge.fury.io/py/sodapy.svg)](http://badge.fury.io/py/sodapy) [![Build Status](https://github.com/afeld/sodapy/actions/workflows/tests.yml/badge.svg)](https://github.com/afeld/sodapy/actions/workflows/tests.yml) [![Code Coverage](https://codecov.io/gh/afeld/sodapy/graph/badge.svg?token=64R1LqdV8I)](https://codecov.io/gh/afeld/sodapy)

# sodapy

sodapy is a Python client for the [Socrata Open Data API (SODA)](https://dev.socrata.com/). It provides read-only access to data and metadata.

Data publishers, see [Socrata's official SDKs and Libraries](https://dev.socrata.com/publishers/) — specifically [socrata-py](https://github.com/socrata/socrata-py?tab=readme-ov-file#readme) — for managing datasets.

## Installation

You can install with `pip install sodapy`.

This package uses [semantic versioning](https://semver.org/).

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
- [`download_attachments`](#download_attachmentsdataset_identifier-content_typejson-download_dirsodapy_downloads)
- [`close`](#close)

### client

Import the library and set up a connection to get started.

```python
from sodapy import Sodapy

client = Sodapy("sandbox.demo.socrata.com")
```

An [application token](https://dev.socrata.com/docs/app-tokens) isn't strictly required, but queries executed from a client without an application token will be subjected to strict throttling limits.

```python
client = Sodapy(
    "sandbox.demo.socrata.com",
    app_token="FakeAppToken",
)
```

[`username` and `password` can be specified for datasets that are private.](https://dev.socrata.com/docs/authentication.html)

A client can also be created with a context manager to obviate the need for teardown:

```python
with Sodapy("sandbox.demo.socrata.com") as client:
    # do some stuff
```

The client, by default, makes requests over HTTPS. To modify this behavior, or to make requests through a proxy, take a look [here](https://github.com/afeld/sodapy/issues/31#issuecomment-302176628).

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
    <generator object Sodapy.get_all at 0x7fa0dc8be7b0>

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

### download_attachments(dataset_identifier, content_type="json", download_dir="~/sodapy_downloads")

Download all attachments associated with a dataset. Return a list of paths to the downloaded files.

    >>> client.download_attachments("nimj-3ivp", download_dir="~/Desktop")
        ['/Users/xmunoz/Desktop/nimj-3ivp/FireIncident_Codes.PDF', '/Users/xmunoz/Desktop/nimj-3ivp/AccidentReport.jpg']

### close()

Close the session when you're finished.

```python
client.close()
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## History

This package was initially created and maintained by [**@xmunoz**](https://github.com/xmunoz). On March 8, 2025, ownership was transferred to [**@afeld**](https://github.com/afeld).
