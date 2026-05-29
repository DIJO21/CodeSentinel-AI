import os
import shutil
import pytest
from src.data.vector_store import SecurityVectorStore

def test_vector_store_workflow():
    temp_dir = "./tests/temp_vector_index"
    
    # Clean up any leftover test folders
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        
    try:
        # 1. Initialize Vector Store (using MiniLM-L6-v2 model)
        store = SecurityVectorStore(dimension=384)
        
        # 2. Add Samples
        samples = [
            {
                "owasp_category": "A03:2021-Injection",
                "description": "SQL injection vulnerability in user login",
                "code_sample": "SELECT * FROM users WHERE name = ' + user"
            },
            {
                "owasp_category": "A02:2021-Cryptographic Failures",
                "description": "Hardcoded MD5 hash utilization",
                "code_sample": "hashlib.md5(passwd.encode())"
            }
        ]
        store.add_samples(samples)
        
        # Check that items were registered in metadata list
        assert len(store.metadata) == 2
        
        # 3. Test Search
        results = store.search("SQL injection", top_k=1)
        assert len(results) == 1
        assert results[0]["owasp_category"] == "A03:2021-Injection"
        
        # 4. Test Save Index
        store.save_index(temp_dir)
        assert os.path.exists(os.path.join(temp_dir, "security.index"))
        assert os.path.exists(os.path.join(temp_dir, "metadata.pkl"))
        
        # 5. Test Load Index
        new_store = SecurityVectorStore(dimension=384)
        new_store.load_index(temp_dir)
        assert len(new_store.metadata) == 2
        
        # Verify search works on reloaded database
        new_results = new_store.search("MD5 hash cipher", top_k=1)
        assert len(new_results) == 1
        assert new_results[0]["owasp_category"] == "A02:2021-Cryptographic Failures"
        
    finally:
        # Cleanup
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
