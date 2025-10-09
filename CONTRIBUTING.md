# Contributing to InfraWare

We love your input! We want to make contributing to InfraWare as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

## Pull Requests

Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests:

1. Fork the repo and create your branch from `master`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](http://choosealicense.com/licenses/mit/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issue tracker](https://github.com/Awez123/Infraware/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/Awez123/Infraware/issues/new); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Development Setup

1. Fork and clone the repo
2. Create a virtual environment: `python -m venv venv`
3. Activate it: `source venv/bin/activate` (Linux/macOS) or `venv\Scripts\activate` (Windows)
4. Install in development mode: `pip install -e ".[dev]"`
5. Install pre-commit hooks: `pre-commit install`

## Testing

Run the test suite:
```bash
pytest tests/
pytest tests/ --cov=infraware  # with coverage
```

## Code Style

We use:
- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking

Run formatting:
```bash
black src/ tests/
isort src/ tests/
flake8 src/ tests/
mypy src/
```

## Adding New Features

1. **Security Rules**: Add new rules to `rules/` directory following the YAML format
2. **Cost Analysis**: Update pricing configs in `config/pricing/`
3. **Commands**: Add new commands to `src/infraware/commands/`
4. **Tests**: Add corresponding tests in `tests/`

## License

By contributing, you agree that your contributions will be licensed under its MIT License.