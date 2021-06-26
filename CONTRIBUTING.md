# How to Contribute

First of all, thank you for taking the time to contribute to this project.
We've tried to make a stable project and try to fix bugs continuously.

## Ways to Contribute

- Report bugs
- Feature request opening an issue
- Contribute code by opening a pull request
- Improve the documentation

## Contribute Code

When contributing code we expect that:
- the code is tested (automatically and manually)
- there is a changelog entry (in `CHANGELOG.md`)
- the package version was adapted if necessary using semantic versioning:
  - MAJOR version when you make incompatible API changes
  - MINOR version when you add functionality in a backwards compatible manner
  - PATCH version when you make backwards compatible bug fixes
- if libraries aren't used for all package usages they are extras
- there is documentation for the code

## Testing & Code Style

Next to the Four-eye principle being enforced for pull requests
there is also an automated test pipeline.

The pipeline runs:
- `pytest` to execute automated tests
- `black`, `flake8` and `isort` for consistent code style
- `bandit` to find well known vulnerabilities

## Documentation

We try to do our best to document the usage of the package in the `README.md`
as well as there are hands-on examples in the wiki.

There are only docstrings in place in the code if they really help to
understand what's going on. Other than that critical endpoints implement
type hinting. Interfaces should be defined for all code which is reused
by the package user.

## Commits and Pull Requests

Commits should be well structured and split into atomic changes.
Checkout [Chris Beams - How to Write a Commit Message](https://chris.beams.io/posts/git-commit/#seven-rules)
to improve on the messages.

One pull request handles one issue/feature and there is an explanation
how it will impact the package and how it is valuable for this project.
