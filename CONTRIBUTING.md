# Contributing to NIDS Project

We love your input! We want to make contributing to this NIDS project as easy and transparent as possible.

## Development Process

1. Fork the repo and create your branch from `main`
2. Make your changes
3. Add tests if applicable
4. Ensure all tests pass
5. Submit a pull request

## Adding New Features

### Detection Rules
- Add clear documentation for new rules
- Include test cases in `test_alerts.py`
- Specify severity levels appropriately

### Code Style
- Follow PEP 8 guidelines
- Use descriptive variable names
- Add comments for complex logic
- Include type hints where possible

### Testing
- Test with various network scenarios
- Verify false positive rates
- Performance testing for high traffic

## Pull Request Process

1. Update README.md if needed
2. Update requirements.txt if adding dependencies
3. Add appropriate tests
4. Ensure CI passes
5. Get review from maintainers

## Bug Reports

When reporting bugs, please include:
- NIDS version
- Operating system
- Network interface details
- Steps to reproduce
- Error logs if available

## Feature Requests

We welcome feature requests! Please provide:
- Use case description
- Expected behavior
- Proposed implementation if possible