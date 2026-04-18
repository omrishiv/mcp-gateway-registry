# Test Maintenance Guide

Guide for maintaining a healthy test suite over time.

## Table of Contents

- [Coverage Monitoring](#coverage-monitoring)
- [When Coverage Drops](#when-coverage-drops)
- [Updating Tests](#updating-tests)
- [Test Performance](#test-performance)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting Flaky Tests](#troubleshooting-flaky-tests)
- [Test Isolation Issues](#test-isolation-issues)
- [Deprecating Tests](#deprecating-tests)

## Coverage Monitoring

### Current Coverage Requirements

The project maintains **80% minimum code coverage** across all source code.

### Checking Current Coverage

Check coverage locally:

```bash
# Quick check
make test-coverage

# Detailed report
uv run pytest --cov=registry --cov-report=term-missing

# HTML report for detailed analysis
uv run pytest --cov=registry --cov-report=html
open htmlcov/index.html
```

### Coverage Reports

Coverage reports show:
- Overall coverage percentage
- Coverage per module
- Missing lines (not covered by tests)
- Branch coverage (conditional paths)

Example output:

```
Name                              Stmts   Miss  Cover   Missing
---------------------------------------------------------------
registry/services/server.py          45      3    93%   12, 45-47
registry/api/routes.py              120     15    88%   78-82, 156-162
registry/core/config.py              25      0   100%
---------------------------------------------------------------
TOTAL                               450     35    92%
```

### Monitoring Coverage in CI/CD

Coverage is automatically checked in CI/CD:

1. **GitHub Actions**: Every PR and commit
2. **Codecov**: Tracks coverage over time
3. **PR Comments**: Shows coverage changes

### Coverage Badges

Add coverage badge to README:

```markdown
[![codecov](https://codecov.io/gh/username/repo/branch/main/graph/badge.svg)](https://codecov.io/gh/username/repo)
```

## When Coverage Drops

### Identifying Uncovered Code

1. **Run coverage report**:
   ```bash
   uv run pytest --cov=registry --cov-report=html
   open htmlcov/index.html
   ```

2. **Check the HTML report**:
   - Red lines: Not covered
   - Yellow lines: Partially covered (some branches)
   - Green lines: Fully covered

3. **Focus on critical paths first**:
   - API endpoints
   - Business logic
   - Error handling
   - Data validation

### Adding Tests for Uncovered Code

Example: Adding tests for uncovered function

```python
# Original uncovered function
def calculate_score(metrics: Dict[str, float]) -> float:
    """Calculate composite score from metrics."""
    if not metrics:
        return 0.0

    total = sum(metrics.values())
    count = len(metrics)
    return total / count


# Add tests to cover this function
@pytest.mark.unit
class TestScoreCalculation:
    """Tests for calculate_score function."""

    def test_calculate_score_with_valid_metrics(self):
        """Test score calculation with valid metrics."""
        metrics = {"metric1": 0.8, "metric2": 0.9, "metric3": 0.7}
        score = calculate_score(metrics)
        assert score == pytest.approx(0.8, rel=0.01)

    def test_calculate_score_with_empty_metrics(self):
        """Test score calculation with no metrics."""
        score = calculate_score({})
        assert score == 0.0

    def test_calculate_score_with_single_metric(self):
        """Test score calculation with single metric."""
        score = calculate_score({"metric1": 0.5})
        assert score == 0.5
```

### Strategies for Improving Coverage

1. **Start with low-hanging fruit**: Test simple functions first
2. **Focus on new code**: Ensure new features have tests
3. **Test error paths**: Add tests for exception handling
4. **Test edge cases**: Boundary conditions, empty inputs, etc.
5. **Add integration tests**: Cover component interactions

## Updating Tests

### When Code Changes

Update tests when code changes:

1. **API changes**: Update API tests
2. **Function signatures**: Update unit tests
3. **New features**: Add new tests
4. **Bug fixes**: Add regression tests
5. **Refactoring**: Update mocks and fixtures

### Test Update Checklist

When updating code:

- [ ] Update affected unit tests
- [ ] Update integration tests if needed
- [ ] Add tests for new functionality
- [ ] Verify all tests still pass
- [ ] Check coverage hasn't dropped
- [ ] Update test documentation

### Example: Updating Tests After Code Change

**Code change**: Add pagination to list_servers endpoint

```python
# Old code
def list_servers():
    return server_service.list_servers()


# New code
def list_servers(page: int = 1, page_size: int = 10):
    return server_service.list_servers_paginated(page, page_size)
```

**Update tests**:

```python
# Old test
def test_list_servers(server_service):
    servers = server_service.list_servers()
    assert isinstance(servers, list)


# Updated test
def test_list_servers_default_pagination(server_service):
    """Test list servers with default pagination."""
    result = server_service.list_servers_paginated(page=1, page_size=10)
    assert isinstance(result["items"], list)
    assert result["page"] == 1
    assert result["page_size"] == 10


def test_list_servers_custom_pagination(server_service):
    """Test list servers with custom pagination."""
    result = server_service.list_servers_paginated(page=2, page_size=5)
    assert result["page"] == 2
    assert result["page_size"] == 5


def test_list_servers_invalid_page_raises_error(server_service):
    """Test invalid page number raises error."""
    with pytest.raises(ValueError):
        server_service.list_servers_paginated(page=0, page_size=10)
```

## Test Performance

### Identifying Slow Tests

Find slow tests:

```bash
# Show test durations
uv run pytest --durations=10

# Show all durations
uv run pytest --durations=0

# Run only slow tests
uv run pytest -m slow
```

### Optimizing Test Performance

1. **Use appropriate fixtures**:
   ```python
   # Good - Function-scoped for isolation
   @pytest.fixture
   def temp_database():
       db = create_database()
       yield db
       db.cleanup()

   # Better - Module-scoped for performance
   @pytest.fixture(scope="module")
   def shared_database():
       db = create_database()
       yield db
       db.cleanup()
   ```

2. **Mock expensive operations**:
   ```python
   # Slow - Real API calls
   def test_fetch_data():
       data = external_api.fetch()
       assert data is not None

   # Fast - Mocked API
   @patch('module.external_api.fetch')
   def test_fetch_data(mock_fetch):
       mock_fetch.return_value = {"data": "test"}
       data = external_api.fetch()
       assert data == {"data": "test"}
   ```

3. **Run tests in parallel**:
   ```bash
   # Install pytest-xdist
   uv add --dev pytest-xdist

   # Run tests in parallel
   uv run pytest -n auto
   ```

4. **Skip slow tests during development**:
   ```python
   # Mark slow tests
   @pytest.mark.slow
   def test_expensive_operation():
       pass

   # Skip in development
   pytest -m "not slow"
   ```

### Test Performance Goals

- **Unit tests**: < 1 second each
- **Integration tests**: < 5 seconds each
- **E2E tests**: < 30 seconds each
- **Total test suite**: < 5 minutes

## CI/CD Integration

### GitHub Actions Configuration

Example test workflow:

```yaml
name: Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.14'

      - name: Install uv
        run: pip install uv

      - name: Install dependencies
        run: uv sync

      - name: Run tests
        run: uv run pytest --cov=registry --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
```

### Handling CI/CD Test Failures

When tests fail in CI/CD:

1. **Check the logs**:
   - Look for error messages
   - Check which test failed
   - Review stack traces

2. **Reproduce locally**:
   ```bash
   # Run the same test
   uv run pytest tests/path/to/test.py::test_name

   # Run with same markers
   uv run pytest -m integration
   ```

3. **Common CI/CD issues**:
   - Missing environment variables
   - Service dependencies not running
   - File permissions
   - Timing-sensitive tests

4. **Fix and verify**:
   - Make necessary changes
   - Run tests locally
   - Push fix
   - Verify CI/CD passes

## Troubleshooting Flaky Tests

### Identifying Flaky Tests

Flaky tests pass/fail intermittently. Signs:
- Tests fail randomly in CI/CD
- Tests pass when run individually
- Tests fail when run with others
- Different results on different machines

### Finding Flaky Tests

Run tests multiple times:

```bash
# Run tests 10 times
for i in {1..10}; do
  uv run pytest tests/test_file.py || echo "Failed on iteration $i"
done

# Use pytest-repeat
uv add --dev pytest-repeat
uv run pytest --count=10 tests/test_file.py
```

### Common Causes of Flaky Tests

1. **Timing issues**:
   ```python
   # Flaky - Depends on timing
   def test_async_operation():
       start_background_task()
       time.sleep(0.1)  # May not be enough
       assert task_complete()

   # Fixed - Wait for condition
   def test_async_operation():
       start_background_task()
       wait_for_condition(lambda: task_complete(), timeout=5)
       assert task_complete()
   ```

2. **Shared state**:
   ```python
   # Flaky - Modifies global state
   def test_with_global_state():
       global_config.update({"key": "value"})
       assert process_data() == expected

   # Fixed - Isolated state
   def test_with_isolated_state(monkeypatch):
       test_config = {"key": "value"}
       monkeypatch.setattr('module.global_config', test_config)
       assert process_data() == expected
   ```

3. **Order dependencies**:
   ```python
   # Flaky - Depends on test order
   def test_first():
       create_resource("test")

   def test_second():
       resource = get_resource("test")  # Assumes test_first ran
       assert resource is not None

   # Fixed - Independent tests
   def test_first():
       create_resource("test1")
       assert get_resource("test1") is not None

   def test_second():
       create_resource("test2")
       assert get_resource("test2") is not None
   ```

4. **Non-deterministic data**:
   ```python
   # Flaky - Random data
   def test_with_random_data():
       data = generate_random_data()
       assert process(data) > 0  # May fail with certain random values

   # Fixed - Deterministic data
   def test_with_fixed_data():
       data = [1, 2, 3, 4, 5]
       assert process(data) == 15
   ```

## Test Isolation Issues

### Ensuring Test Isolation

Tests should not affect each other:

```python
# Bad - Tests share state
class TestSharedState:
    shared_list = []

    def test_append(self):
        self.shared_list.append(1)
        assert len(self.shared_list) == 1  # Fails on second run

    def test_length(self):
        assert len(self.shared_list) == 0  # Fails if test_append ran first


# Good - Tests are isolated
class TestIsolatedState:
    def test_append(self):
        test_list = []
        test_list.append(1)
        assert len(test_list) == 1

    def test_length(self):
        test_list = []
        assert len(test_list) == 0
```

### Using Fixtures for Isolation

```python
@pytest.fixture
def isolated_list():
    """Provide a fresh list for each test."""
    return []


def test_append(isolated_list):
    isolated_list.append(1)
    assert len(isolated_list) == 1


def test_length(isolated_list):
    assert len(isolated_list) == 0
```

### Cleanup After Tests

Always cleanup:

```python
@pytest.fixture
def temp_file():
    """Create and cleanup temporary file."""
    path = Path("temp.txt")
    path.write_text("test")

    yield path

    # Cleanup
    if path.exists():
        path.unlink()


@pytest.fixture
def database():
    """Create and cleanup test database."""
    db = create_database()

    yield db

    # Cleanup
    db.drop_all_tables()
    db.close()
```

## Deprecating Tests

### When to Deprecate Tests

Deprecate tests when:
- Feature is removed
- API is changed significantly
- Test is replaced by better test
- Test is no longer relevant

### How to Deprecate Tests

1. **Mark as deprecated**:
   ```python
   @pytest.mark.skip(reason="Deprecated - Use test_new_feature instead")
   def test_old_feature():
       pass
   ```

2. **Add deprecation warning**:
   ```python
   import warnings

   def test_legacy_feature():
       warnings.warn(
           "This test is deprecated and will be removed in v2.0",
           DeprecationWarning
       )
       # Test code...
   ```

3. **Document migration path**:
   ```python
   # DEPRECATED: This test is deprecated as of v1.5.0
   # Use test_new_implementation in test_new_feature.py instead
   # Will be removed in v2.0.0
   @pytest.mark.skip(reason="Deprecated - see test_new_implementation")
   def test_old_implementation():
       pass
   ```

## Best Practices

1. **Monitor coverage regularly**: Check coverage on every PR
2. **Keep tests fast**: Optimize slow tests
3. **Fix flaky tests immediately**: Don't ignore them
4. **Update tests with code**: Tests are part of the codebase
5. **Document test patterns**: Help others write good tests
6. **Review test code**: Tests deserve code review too
7. **Refactor tests**: Keep test code clean
8. **Delete obsolete tests**: Remove tests for removed features

## Maintenance Checklist

### Weekly

- [ ] Review test failures in CI/CD
- [ ] Check for slow tests
- [ ] Monitor coverage trends

### Monthly

- [ ] Review and fix flaky tests
- [ ] Update test dependencies
- [ ] Refactor duplicate test code
- [ ] Update test documentation

### Quarterly

- [ ] Audit test coverage
- [ ] Remove obsolete tests
- [ ] Review test performance
- [ ] Update testing guidelines

## Summary

Key maintenance tasks:

1. Monitor and maintain 80% coverage
2. Keep tests fast and reliable
3. Fix flaky tests immediately
4. Ensure test isolation
5. Update tests with code changes
6. Optimize test performance
7. Clean up obsolete tests

For more information, see:
- [Testing Guide](./README.md)
- [Writing Tests Guide](./WRITING_TESTS.md)
