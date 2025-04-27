# Contributing

This project adheres to the [Contributor Covenant Code of Conduct](http://contributor-covenant.org/version/1/4/). By participating, you are expected to honor this code.

## Getting started

This project uses [uv](https://docs.astral.sh/uv/) for packaging. To get set up:

```sh
git clone <my remote url/sodapy.git>
cd sodapy
```

Run tests, which will also install packages:

```sh
uv run pytest --cov
```

## Submitting a pull request

1. Fork this repository
2. Create a branch: `git checkout -b my_feature`
3. Make changes
4. Run `uv run black sodapy tests` to ensure that your changes conform to the coding style of this project
5. Commit: `git commit -am "Great new feature that closes #3"`. Reference any related issues in the first line of the commit message.
6. Push: `git push origin my_feature`
7. Open a pull request
8. Pat yourself on the back for making an open source contribution :)

## Other considerations

- Please review the open issues before opening a PR.
- Significant changes or new features should be documented in [the README](README.md).
- Writing tests is never a bad idea. Make sure all tests are passing before opening a PR.
