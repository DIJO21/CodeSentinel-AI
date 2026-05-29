
import faiss
import numpy as np
import pickle
import os

from sentence_transformers import SentenceTransformer

class SecurityVectorStore:

    def __init__(self, dimension=384):

        self.dimension = dimension

        self.index = faiss.IndexFlatL2(dimension)

        self.metadata = []

        self.encoder = SentenceTransformer(
            "sentence-transformers/all-MiniLM-L6-v2"
        )

    def add_samples(self, samples):

        texts = []

        for sample in samples:

            combined = (
                sample.get("owasp_category", "") + " " +
                sample.get("description", "") + " " +
                sample.get("code_sample", "")
            )

            texts.append(combined)

            self.metadata.append(sample)

        embeddings = self.encoder.encode(texts)

        embeddings = np.array(embeddings).astype("float32")

        self.index.add(embeddings)

        print(f"✅ Added {len(samples)} samples")

    def search(self, query, top_k=3):

        query_embedding = self.encoder.encode([query])

        query_embedding = np.array(query_embedding).astype("float32")

        distances, indices = self.index.search(query_embedding, top_k)

        results = []

        for idx in indices[0]:

            if idx < len(self.metadata):
                results.append(self.metadata[idx])

        return results

    def save_index(self, path):

        os.makedirs(path, exist_ok=True)

        faiss.write_index(
            self.index,
            os.path.join(path, "security.index")
        )

        with open(
            os.path.join(path, "metadata.pkl"),
            "wb"
        ) as f:

            pickle.dump(self.metadata, f)

        print(f"✅ Index saved to {path}")

    def load_index(self, path):
        self.index = faiss.read_index(os.path.join(path, "security.index"))
        with open(os.path.join(path, "metadata.pkl"), "rb") as f:
            self.metadata = pickle.load(f)
        print(f"✅ Index loaded from {path}")

