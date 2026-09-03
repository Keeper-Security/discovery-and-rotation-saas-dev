from __future__ import annotations
import unittest
import sys
import subprocess
import importlib.util
from pathlib import Path
try:
    import coverage
    HAS_COVERAGE = True
except ImportError:
    HAS_COVERAGE = False


class TestAllIntegrations(unittest.TestCase):
    """Discover and run all integration tests"""

    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.project_root = Path(__file__).parent.parent
        cls.integrations_dir = cls.project_root / "integrations"

    def test_discover_and_run_integrations(self):
        """Find all integration directories and run their tests"""

        if not self.integrations_dir.exists():
            self.fail(f"Integrations directory not found: {self.integrations_dir}")

        # Find all integration directories (exclude __pycache__ and __init__.py)
        integration_dirs = [
            d for d in self.integrations_dir.iterdir()
            if d.is_dir() and not d.name.startswith('__') and not d.name.startswith('.')
        ]

        if not integration_dirs:
            self.fail(f"No integration directories found in {self.integrations_dir}")

        print(f"\nFound {len(integration_dirs)} integration(s) to test")

        all_results = {}
        failed_integrations = []

        for integration_dir in sorted(integration_dirs):
            integration_name = integration_dir.name
            print(f"\n{'='*60}")
            print(f"Testing integration: {integration_name}")
            print(f"{'='*60}")

            # Find test files in this integration directory
            test_files = list(integration_dir.glob("*_test.py"))

            if not test_files:
                print(f"  ⚠️  No test files found for {integration_name}")
                all_results[integration_name] = "NO_TESTS"
                continue

            # Check for requirements_test.txt and install dependencies
            requirements_file = integration_dir / "requirements_test.txt"
            if requirements_file.exists():
                print(f"  📦 Installing test dependencies from requirements_test.txt...")
                try:
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "-q", "-r", str(requirements_file)],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    if result.returncode != 0:
                        print(f"    ⚠️  Warning: pip install failed: {result.stderr}")
                    else:
                        print(f"    ✅ Dependencies installed")
                except subprocess.TimeoutExpired:
                    print(f"    ⚠️  Warning: pip install timed out")
                except Exception as e:
                    print(f"    ⚠️  Warning: pip install error: {e}")

            # Add integration directory to Python path so imports work
            integration_path = str(integration_dir)
            original_path = sys.path.copy()

            try:
                # Insert at the beginning so this integration's imports are prioritized
                sys.path.insert(0, integration_path)
                sys.path.insert(0, str(self.project_root))

                loader = unittest.TestLoader()
                suite = unittest.TestSuite()

                for test_file in test_files:
                    print(f"  Loading tests from: {test_file.name}")

                    try:
                        # Load the module from file path
                        module_name = f"integrations.{integration_name}.{test_file.stem}"
                        spec = importlib.util.spec_from_file_location(module_name, test_file)

                        if spec is None or spec.loader is None:
                            raise ImportError(f"Could not load spec for {test_file}")

                        module = importlib.util.module_from_spec(spec)
                        sys.modules[module_name] = module
                        spec.loader.exec_module(module)

                        # Load tests from the module
                        tests = loader.loadTestsFromModule(module)
                        suite.addTests(tests)

                    except Exception as e:
                        print(f"    ⚠️  Error loading {test_file.name}: {e}")
                        all_results[integration_name] = f"LOAD_ERROR: {str(e)}"
                        failed_integrations.append(integration_name)
                        break

                else:
                    # Run the tests (only if no load errors occurred)
                    runner = unittest.TextTestRunner(verbosity=2)
                    result = runner.run(suite)

                    # Calculate coverage if available
                    coverage_percent = None
                    if HAS_COVERAGE and result.wasSuccessful():
                        # Find the main plugin Python file (not test file)
                        plugin_files = [
                            f for f in integration_dir.glob("*.py")
                            if not f.name.endswith('_test.py') and f.name != '__init__.py'
                        ]

                        if plugin_files:
                            try:
                                # Run coverage on the test file
                                test_file = list(integration_dir.glob("*_test.py"))[0]

                                result_cov = subprocess.run(
                                    [
                                        sys.executable, "-m", "coverage", "run",
                                        "--source", str(integration_dir),
                                        "--omit", "*_test.py,*/__pycache__/*",
                                        "-m", "unittest",
                                        f"integrations.{integration_name}.{test_file.stem}"
                                    ],
                                    capture_output=True,
                                    text=True,
                                    timeout=60,
                                    cwd=str(self.project_root)
                                )

                                if result_cov.returncode == 0:
                                    # Get coverage report
                                    result_report = subprocess.run(
                                        [sys.executable, "-m", "coverage", "report", "--omit", "*_test.py"],
                                        capture_output=True,
                                        text=True,
                                        timeout=30
                                    )

                                    # Parse coverage percentage from output
                                    for line in result_report.stdout.split('\n'):
                                        if 'TOTAL' in line:
                                            parts = line.split()
                                            if len(parts) >= 4:
                                                try:
                                                    coverage_percent = float(parts[-1].rstrip('%'))
                                                    statements = parts[1]
                                                    covered = parts[2]
                                                    print(f"  📊 Coverage: {coverage_percent:.1f}% ({covered}/{statements} statements)")
                                                except (ValueError, IndexError):
                                                    pass
                                            break

                                    # Clean up coverage data
                                    subprocess.run(
                                        [sys.executable, "-m", "coverage", "erase"],
                                        capture_output=True,
                                        timeout=10
                                    )
                            except Exception as e:
                                print(f"  ⚠️  Coverage calculation failed: {e}")

                    # Store results
                    if result.wasSuccessful():
                        status = "PASSED"
                        if coverage_percent is not None:
                            status = f"PASSED ({coverage_percent:.1f}% coverage)"
                        all_results[integration_name] = status
                        print(f"  ✅ {integration_name}: All tests passed")
                    else:
                        all_results[integration_name] = "FAILED"
                        failed_integrations.append(integration_name)
                        print(f"  ❌ {integration_name}: Tests failed")

            except Exception as e:
                all_results[integration_name] = f"ERROR: {str(e)}"
                failed_integrations.append(integration_name)
                print(f"  ❌ {integration_name}: Error running tests - {e}")

            finally:
                # Restore original Python path
                sys.path = original_path

        # Print summary
        print(f"\n{'='*60}")
        print("TEST SUMMARY")
        print(f"{'='*60}")
        for name, status in sorted(all_results.items()):
            status_symbol = "✅" if status.startswith("PASSED") else "⚠️" if status == "NO_TESTS" else "❌"
            print(f"{status_symbol} {name}: {status}")

        print(f"\nTotal integrations: {len(all_results)}")
        print(f"Passed: {sum(1 for s in all_results.values() if s.startswith('PASSED'))}")
        print(f"Failed: {len(failed_integrations)}")
        print(f"No tests: {sum(1 for s in all_results.values() if s == 'NO_TESTS')}")

        # Fail the test if any integration tests failed
        if failed_integrations:
            self.fail(f"The following integrations had test failures: {', '.join(failed_integrations)}")


if __name__ == '__main__':
    unittest.main()
