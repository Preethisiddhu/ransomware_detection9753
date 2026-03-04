import numpy as np
import pandas as pd
from typing import List, Tuple

def build_sequences_from_ransomware_df(
    df: pd.DataFrame,
    seq_len: int = 10
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Build sliding-window sequences from the ransomware IRP dataset.
    CSV columns are all numeric: Time, IRP Operation, FSF Operation, etc.

    Returns:
      X: (num_sequences, seq_len, num_features)
      y: (num_sequences,)  -- currently all 1 (ransomware)
    """
    # Use all columns except label as features (all numeric in this CSV)
    feature_cols = [c for c in df.columns if c != "label"]
    if "Time" in df.columns:
        df = df.sort_values("Time").reset_index(drop=True)
    else:
        df = df.reset_index(drop=True)

    features = df[feature_cols].fillna(0).astype("float32").values
    num_rows, num_features = features.shape

    sequences: List[np.ndarray] = []
    labels: List[int] = []

    # Sliding window
    if num_rows < seq_len:
        # pad single sequence
        pad = np.zeros((seq_len - num_rows, num_features), dtype="float32")
        seq = np.vstack([pad, features])
        sequences.append(seq)
        labels.append(1)
    else:
        for start in range(0, num_rows - seq_len + 1):
            end = start + seq_len
            seq = features[start:end]
            sequences.append(seq)
            labels.append(1)

    X = np.stack(sequences)  # (N, T, F)
    y = np.array(labels, dtype="int32")
    return X, y