# Contributing

This project adheres to the [Contributor Covenant Code of Conduct](http://contributor-covenant.org/version/1/4/). By participating, you are expected to honor this code.

## Getting started

The best way to start developing this project is to set up a [virtualenv](https://virtualenv.pypa.io/en/stable/) and install the requirements.

```sh
git clone <my remote url/sodapy.git>
cd sodapy
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

Install the package, and run tests to confirm that everything is set up properly.

```sh
pip install .
pytest
```

## Submitting a pull request

1. Fork this repository
2. Create a branch: `git checkout -b my_feature`
3. Make changes
4. Run `black sodapy tests` to ensure that your changes conform to the coding style of this project
5. Commit: `git commit -am "Great new feature that closes #3"`. Reference any related issues in the first line of the commit message.
6. Push: `git push origin my_feature`
7. Open a pull request
8. Pat yourself on the back for making an open source contribution :)

## Other considerations

- Please review the open issues before opening a PR.
- Significant changes or new features should be documented in [`README.md`](https://github.com/xmunoz/sodapy/blob/master/README.md).
- Writing tests is never a bad idea. Make sure all tests are passing before opening a PR.
