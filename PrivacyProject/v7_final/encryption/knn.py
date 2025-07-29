import numpy as np

# Euclidean dis
def compute_similarity(query_vector, record_vector):

    return np.linalg.norm(np.array(query_vector) - np.array(record_vector))

def knn_search(query_vector, records, k=3):

    records_with_distance = [
        (record, compute_similarity(query_vector, vector))
        for record, vector in records
    ]
    records_with_distance.sort(key=lambda x: x[1])
    return [record for record, dist in records_with_distance[:k]]
