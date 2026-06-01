#!/usr/bin/env python3
"""Test suite for the Whitelist implementation."""

import asyncio
import tempfile
from pathlib import Path

from antyswirusd.modules.whitelist import Whitelist


async def test_whitelist_basic_workflow():
    """Test basic whitelist operations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        db_path = tmpdir_path / "whitelist.db"

        whitelist = Whitelist(db_path)
        await whitelist.open()

        # Create test files
        test_file1 = tmpdir_path / "safe_file1.txt"
        test_file1.write_text("safe content 1")

        test_file2 = tmpdir_path / "safe_file2.txt"
        test_file2.write_text("safe content 2")

        # Add files to whitelist
        await whitelist.add(str(test_file1), "hash_abc123")
        print("✓ Added file 1 to whitelist")

        await whitelist.add(str(test_file2), "hash_def456")
        print("✓ Added file 2 to whitelist")

        # Test contains_path
        is_whitelisted = await whitelist.contains_path(test_file1)
        assert is_whitelisted, "File should be whitelisted"
        print("✓ contains_path() works correctly")

        # Test contains_hash
        has_hash = await whitelist.contains_hash("hash_abc123")
        assert has_hash, "Hash should exist in whitelist"
        print("✓ contains_hash() works correctly")

        # Test list
        whitelisted_paths = await whitelist.list()
        assert len(whitelisted_paths) == 2
        print(f"✓ list() returned {len(whitelisted_paths)} paths")

        # Test list_with_hashes
        whitelisted_dict = await whitelist.list_with_hashes()
        assert len(whitelisted_dict) == 2
        assert whitelisted_dict[str(test_file1)] == "hash_abc123"
        assert whitelisted_dict[str(test_file2)] == "hash_def456"
        print("✓ list_with_hashes() returned correct path/hash dictionary")

        # Test remove
        await whitelist.remove(str(test_file1))
        print("✓ Removed file 1 from whitelist")

        is_whitelisted = await whitelist.contains_path(test_file1)
        assert not is_whitelisted, "File should no longer be whitelisted"
        print("✓ File successfully removed from whitelist")

        whitelisted_paths = await whitelist.list()
        assert len(whitelisted_paths) == 1
        print("✓ Whitelist now contains 1 path")

        await whitelist.close()
        print("✓ Whitelist closed")

        print("\n✓ All basic workflow tests passed!")


async def test_hash_deduplication():
    """Test that removing a path removes all matching hashes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        db_path = tmpdir_path / "whitelist.db"

        whitelist = Whitelist(db_path)
        await whitelist.open()

        # Add multiple files with the same hash (e.g., hardlinks or copies)
        file1 = tmpdir_path / "file1.txt"
        file2 = tmpdir_path / "file2.txt"
        file3 = tmpdir_path / "file3.txt"

        file1.write_text("content")
        file2.write_text("content")
        file3.write_text("content")

        # All three files have the same hash
        shared_hash = "shared_hash_xyz"
        await whitelist.add(str(file1), shared_hash)
        await whitelist.add(str(file2), shared_hash)
        await whitelist.add(str(file3), shared_hash)

        print(f"✓ Added 3 files with shared hash: {shared_hash[:16]}")

        # Verify all are in whitelist
        paths = await whitelist.list()
        assert len(paths) == 3
        print("✓ All 3 files are whitelisted")

        # Remove one file
        await whitelist.remove(str(file1))
        print("✓ Removed file1 from whitelist")

        # All three should be gone because they share the same hash
        has_hash = await whitelist.contains_hash(shared_hash)
        assert not has_hash, "Hash should be removed when last file deleted"
        print("✓ All files with shared hash were removed")

        paths = await whitelist.list()
        assert len(paths) == 0
        print("✓ Whitelist is now empty")

        await whitelist.close()
        print("\n✓ Hash deduplication test passed!")


async def test_file_hash_computation():
    """Test automatic file hash computation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        db_path = tmpdir_path / "whitelist.db"

        whitelist = Whitelist(db_path)
        await whitelist.open()

        test_file = tmpdir_path / "test.bin"
        test_file.write_bytes(b"test content for hashing")

        # Add without specifying hash (should compute it)
        await whitelist.add(str(test_file))
        print("✓ Added file with automatic hash computation")

        # Verify it was added
        is_whitelisted = await whitelist.contains_path(test_file)
        assert is_whitelisted, "File should be whitelisted"
        print("✓ File was successfully added with computed hash")

        # Get the hash
        dict_result = await whitelist.list_with_hashes()
        computed_hash = dict_result[str(test_file)]
        print(f"✓ Computed hash: {computed_hash[:16]}...")

        # Verify hash exists
        has_hash = await whitelist.contains_hash(computed_hash)
        assert has_hash, "Computed hash should be in whitelist"
        print("✓ Computed hash is queryable")

        await whitelist.close()
        print("\n✓ File hash computation test passed!")


async def test_error_handling():
    """Test error handling."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        db_path = tmpdir_path / "whitelist.db"

        whitelist = Whitelist(db_path)
        await whitelist.open()

        # Try to add non-existent file without providing hash
        nonexistent = tmpdir_path / "nonexistent.txt"
        try:
            await whitelist.add(str(nonexistent))
            assert False, "Should raise error for nonexistent file"
        except FileNotFoundError:
            print("✓ FileNotFoundError raised for nonexistent file")

        # Try to remove non-existent file (should not crash)
        try:
            await whitelist.remove(str(nonexistent))
            print("✓ Remove handles non-existent files gracefully")
        except Exception as e:
            print(f"✓ Remove raised {type(e).__name__} for non-existent file")

        # Test adding with explicit hash (no file required)
        fake_path = "/fake/path/file.txt"
        await whitelist.add(fake_path, "manual_hash_123")
        print("✓ Can add paths with explicit hash (no file verification)")

        is_whitelisted = await whitelist.contains_path(Path(fake_path))
        assert is_whitelisted
        print("✓ Fake path is whitelisted")

        await whitelist.close()
        print("\n✓ Error handling tests passed!")


async def test_concurrent_operations():
    """Test thread-safe concurrent operations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        db_path = tmpdir_path / "whitelist.db"

        whitelist = Whitelist(db_path)
        await whitelist.open()

        # Create multiple files
        files = []
        for i in range(10):
            f = tmpdir_path / f"file{i}.txt"
            f.write_text(f"content {i}")
            files.append(f)

        # Add all files concurrently
        tasks = [
            whitelist.add(str(f), f"hash_{i}") for i, f in enumerate(files)
        ]
        await asyncio.gather(*tasks)
        print("✓ Added 10 files concurrently")

        # Query all files concurrently
        tasks = [whitelist.contains_path(f) for f in files]
        results = await asyncio.gather(*tasks)
        assert all(results), "All files should be whitelisted"
        print("✓ All concurrent queries returned True")

        paths = await whitelist.list()
        assert len(paths) == 10
        print("✓ All 10 files are in whitelist")

        await whitelist.close()
        print("\n✓ Concurrent operations test passed!")


async def main():
    print("Testing Whitelist Implementation")
    print("=" * 50)
    print("\n1. Testing basic workflow...")
    await test_whitelist_basic_workflow()
    print("\n2. Testing hash deduplication...")
    await test_hash_deduplication()
    print("\n3. Testing file hash computation...")
    await test_file_hash_computation()
    print("\n4. Testing error handling...")
    await test_error_handling()
    print("\n5. Testing concurrent operations...")
    await test_concurrent_operations()


if __name__ == "__main__":
    asyncio.run(main())
