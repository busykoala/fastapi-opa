# How to contribute

First of all, thank you for taking the time to contribute to this project.
The contributors try to make a stable project improving continuously.

## Ways to contribute

- Report bugs
- Feature request opening an issue
- Contribute code by opening a pull request
- Improve the documentation

## Contribute code

When contributing code make sure that:
- you test the code automatically and manually
- there is a changelog entry in `CHANGELOG.md`
- adapt the package with semantic versioning:
  - `MAJOR` version when you make incompatible API changes
  - `MINOR` version when you add features in a backwards compatible manner
  - `PATCH` version when you make backwards compatible bug fixes
- if libraries aren't used for all package usages they're extras
- there is documentation for the code

## Testing & code style

For pull requests there is the four-eye principle applied whenever possible.
Additionally there is an automated test pipeline which runs:
- `pytest` to execute automated tests
- `black`, `flake8` and `isort` for consistent code style
- `bandit` to find well known vulnerabilities

## Documentation

The crucial part of the documentation is in the `README.md`.
Hands-on examples and detailed explanations go into the wiki.

There are only docstrings in place in the code if they really help to
understand what's going on. Other than that critical endpoints implement type
hinting. Define interfaces for all code used when implementing the package.

Use [vale](https://vale.sh/) to lint `README.md` and `CONTRIBUTING.md`. After
installing `vale` run `vale README.md CONTRIBUTING.md` to get the errors,
warnings and suggestions.

## Commits and pull requests

Commits should be well structured and split into atomic changes.
Checkout [Chris Beams - How to Write a Commit Message](https://chris.beams.io/posts/git-commit/#seven-rules)
to improve on the messages.

One pull request handles one issue/feature and there is an explanation
how it impacts the package and how it's valuable for this project.
