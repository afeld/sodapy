# Contributing

This project adheres to the [Contributor Covenant Code of Conduct](http://contributor-covenant.org/version/1/4/). By participating, you are expected to honor this code.

## Getting started

This project uses [uv](https://docs.astral.sh/uv/) for packaging. To get set up:

1. [Fork the repository.](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo)
1. [Clone the repository.](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository)
1. [Install uv.](https://docs.astral.sh/uv/getting-started/installation/)
1. From the repository directory, run tests, which will also install packages:

   ```sh
   uv run pytest --cov
   ```

## Submitting a pull request

1. Fork this repository
1. Create a branch: `git checkout -b my_feature`
1. Make changes
1. Run `uvx ruff check` to run static analysis.
1. Run `uvx ruff format` to ensure that your changes conform to the coding style of this project.
1. Commit: `git commit -am "Great new feature that closes #3"`. Reference any related issues in the first line of the commit message.
1. Push: `git push origin my_feature`
1. Open a pull request
1. Pat yourself on the back for making an open source contribution :)

## Other considerations

- Please review the open issues before opening a PR.
- Significant changes or new features should be documented in [the README](README.md).
- Writing tests is never a bad idea. Make sure all tests are passing before opening a PR.
