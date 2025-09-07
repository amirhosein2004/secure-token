"""
SecureToken Performance Benchmark Script

This script tests the system's speed and efficiency under various conditions
"""

import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from src.secure_token import SecureTokenManager


class TokenBenchmark:
    """Token Benchmark Class"""

    def __init__(self):
        self.manager = SecureTokenManager()
        self.results = {}

    def benchmark_token_generation(self, count=1000):
        """Benchmark token generation"""
        print(f"Testing generation of {count} tokens...")

        times = []
        tokens = []

        for i in range(count):
            start = time.perf_counter()
            token = self.manager.generate_token(
                user_id=f"user_{i}", permissions=["read", "write"], expires_in_hours=24
            )
            end = time.perf_counter()

            times.append(end - start)
            tokens.append(token)

        self.results["generation"] = {
            "count": count,
            "total_time": sum(times),
            "avg_time": statistics.mean(times),
            "min_time": min(times),
            "max_time": max(times),
            "tokens_per_second": count / sum(times),
        }

        print(f"Average generation time: {self.results['generation']['avg_time']*1000: .2f}ms")
        print(
            f"Generation speed: {self.results['generation']['tokens_per_second']: .1f} tokens/second"
        )

        return tokens

    def benchmark_token_validation(self, tokens):
        """Benchmark token validation"""
        print(f"Testing validation of {len(tokens)} tokens...")

        times = []
        valid_count = 0

        for token in tokens:
            start = time.perf_counter()
            try:
                result = self.manager.validate_token(token)
                end = time.perf_counter()
                times.append(end - start)
                if result["valid"]:
                    valid_count += 1
            except Exception:
                # Token validation failed
                end = time.perf_counter()
                times.append(end - start)

        self.results["validation"] = {
            "count": len(tokens),
            "valid_count": valid_count,
            "total_time": sum(times),
            "avg_time": statistics.mean(times),
            "validations_per_second": len(tokens) / sum(times),
        }

        print(f"Average validation time: {self.results['validation']['avg_time']*1000: .2f}ms")
        print(
            f"Validation speed: {self.results['validation']['validations_per_second']: .1f} validations/second"
        )
        print(f"Valid tokens: {valid_count}/{len(tokens)}")

    def benchmark_concurrent_generation(self, total_tokens=1000, max_workers=10):
        """Benchmark concurrent generation"""
        print(f"Testing concurrent generation with {max_workers} workers...")

        def generate_batch(start_idx, count):
            batch_manager = SecureTokenManager()  # Each thread has a separate manager
            tokens = []
            for i in range(start_idx, start_idx + count):
                token = batch_manager.generate_token(
                    user_id=f"concurrent_user_{i}", permissions=["read"], expires_in_hours=24
                )
                tokens.append(token)
            return tokens

        batch_size = total_tokens // max_workers

        start_time = time.perf_counter()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for i in range(0, total_tokens, batch_size):
                future = executor.submit(generate_batch, i, min(batch_size, total_tokens - i))
                futures.append(future)

            all_tokens = []
            for future in futures:
                all_tokens.extend(future.result())

        end_time = time.perf_counter()

        self.results["concurrent"] = {
            "total_tokens": len(all_tokens),
            "workers": max_workers,
            "total_time": end_time - start_time,
            "tokens_per_second": len(all_tokens) / (end_time - start_time),
        }

        print(f"Concurrent generation of {len(all_tokens)} tokens in {end_time - start_time: .2f}s")
        print(
            f"Concurrent speed: {self.results['concurrent']['tokens_per_second']: .1f} tokens/second"
        )

        return all_tokens

    def benchmark_memory_usage(self, token_count=10000):
        """Benchmark memory usage"""
        print(f"Testing memory usage for {token_count} tokens...")

        import gc

        import psutil

        process = psutil.Process()

        # Memory before generation
        gc.collect()
        memory_before = process.memory_info().rss / 1024 / 1024  # MB

        # Generate tokens
        start_time = time.perf_counter()
        for i in range(token_count):
            self.manager.generate_token(
                user_id=f"memory_test_user_{i}", permissions=["read"], expires_in_hours=24
            )
        end_time = time.perf_counter()

        # Memory after generation
        gc.collect()
        memory_after = process.memory_info().rss / 1024 / 1024  # MB

        memory_per_token = (memory_after - memory_before) * 1024 / token_count  # KB

        self.results["memory"] = {
            "token_count": token_count,
            "memory_before": memory_before,
            "memory_after": memory_after,
            "memory_used": memory_after - memory_before,
            "memory_per_token": memory_per_token,
            "generation_time": end_time - start_time,
        }

        print(f"Memory before: {memory_before: .1f}MB")
        print(f"Memory after: {memory_after: .1f}MB")
        print(f"Memory increase: {memory_after - memory_before: .1f}MB")
        print(f"Memory per token: {memory_per_token: .2f}KB")

    def run_full_benchmark(self):
        """Run full benchmark"""
        print("Starting full SecureToken benchmark")
        print("=" * 50)

        # Generation
        tokens = self.benchmark_token_generation(1000)
        print()

        # Validation
        self.benchmark_token_validation(tokens)
        print()

        # Concurrency
        self.benchmark_concurrent_generation(1000, 10)
        print()

        # Memory
        self.benchmark_memory_usage(5000)
        print()

        # Summary of results
        self.print_summary()

    def print_summary(self):
        """Print summary of results"""
        print("Benchmark Results Summary")
        print("=" * 50)

        if "generation" in self.results:
            gen = self.results["generation"]
            print("Token Generation:")
            print(f"   • Speed: {gen['tokens_per_second']: .1f} tokens/second")
            print(f"   • Average time: {gen['avg_time']*1000: .2f}ms")

        if "validation" in self.results:
            val = self.results["validation"]
            print("Validation:")
            print(f"   • Speed: {val['validations_per_second']: .1f} validations/second")
            print(f"   • Average time: {val['avg_time']*1000: .2f}ms")

        if "concurrent" in self.results:
            conc = self.results["concurrent"]
            print("Concurrent Generation:")
            print(f"   • Speed: {conc['tokens_per_second']: .1f} tokens/second")
            print(f"   • Workers: {conc['workers']}")

        if "memory" in self.results:
            mem = self.results["memory"]
            print("Memory Usage:")
            print(f"   • Per token: {mem['memory_per_token']: .2f}KB")
            print(f"   • Total used: {mem['memory_used']: .1f}MB")

        print("\nBenchmark finished!")


if __name__ == "__main__":
    benchmark = TokenBenchmark()

    if len(sys.argv) > 1:
        test_type = sys.argv[1].lower()

        if test_type == "generation":
            count = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
            benchmark.benchmark_token_generation(count)
        elif test_type == "validation":
            tokens = benchmark.benchmark_token_generation(100)
            benchmark.benchmark_token_validation(tokens)
        elif test_type == "concurrent":
            total = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
            workers = int(sys.argv[3]) if len(sys.argv) > 3 else 10
            benchmark.benchmark_concurrent_generation(total, workers)
        elif test_type == "memory":
            count = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
            benchmark.benchmark_memory_usage(count)
        else:
            print("❌ Invalid test type. Allowed types: generation, validation, concurrent, memory")
    else:
        benchmark.run_full_benchmark()
