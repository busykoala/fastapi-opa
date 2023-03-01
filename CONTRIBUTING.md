# How to contribute

Thanks for your interest in contributing. The project's contributors strive to
maintain stability and continually make improvements.

## Ways to contribute

- Report bugs
- Feature request opening an issue
- Contribute code by opening a pull request
- Improve the documentation

## Contribute code

When contributing code make sure that:
- you test the code automatically and manually
- you add a changelog entry to `CHANGELOG.md`
- you adapt the package with semantic versioning:
  - `MAJOR` version when you make incompatible API changes
  - `MINOR` version when you add features in a backwards compatible manner
  - `PATCH` version when you make backwards compatible bug fixes
- you put third party libraries into extras if not necessary for every use case
- you provide documentation

## Testing & code style

Whenever possible a second person reviews pull requests.
Furthermore an automated test pipeline runs with:
- `pytest` to execute automated tests
- `black`, `flake8` and `isort` for consistent code style
- `bandit` to find well known vulnerabilities

## Documentation

Document the package within `README.md`.
Hands-on examples and detailed explanations go into the wiki.

Limit docstrings to places in the code where they help to understand what goes
on. Other than that critical endpoints use type hinting. Define interfaces for
all code used for implementing the package.

Use [vale](https://vale.sh/) to lint `README.md` and `CONTRIBUTING.md`.
Run `poetry run vale README.md CONTRIBUTING.md` to get the errors,
warnings and suggestions.

## Commits and pull requests

Structure commits well and split into atomic changes.
Checkout [Chris Beams - How to Write a Commit Message](https://chris.beams.io/posts/git-commit/#seven-rules)
to improve on the messages.

One pull request handles one issue/feature and it explains
how it impacts the package and describes the value for this project.
