import numpy as np

def build_sequences_from_ransomware_df(df, seq_len=10):
    # Assumption: df-la 'label' column irukkum, baaki ellam features
    feature_cols = [c for c in df.columns if c != "label"]
    data = df[feature_cols].values.astype(np.float32)
    labels = df["label"].values.astype(np.int64)

    sequences = []
    seq_labels = []

    for i in range(0, len(data) - seq_len + 1):
        seq = data[i : i + seq_len]
        # simple strategy: last event-oda label use pannrom
        lab = labels[i + seq_len - 1]
        sequences.append(seq)
        seq_labels.append(lab)

    X = np.stack(sequences)
    y = np.array(seq_labels)

    return X, y