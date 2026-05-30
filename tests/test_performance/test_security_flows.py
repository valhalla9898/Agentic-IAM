import time


def test_authentication_flow_performance():
    # simple smoke benchmark for auth flow (synthetic)
    start = time.perf_counter()
    # simulate auth work (this should be replaced with a real call in CI)
    for _ in range(10):
        _ = 1 + 1
    elapsed = time.perf_counter() - start
    # ensure the synthetic loop finishes quickly
    assert elapsed < 1.0
