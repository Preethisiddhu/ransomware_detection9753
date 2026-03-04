import os
import sys

# Ensure project root is on path when run as script or module
_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_script_dir, "..", ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import numpy as np
from tensorflow.keras.callbacks import EarlyStopping
from src.data.load_irp_dataset import load_ransomware_irp_dataset
from src.data.build_sequences import build_sequences_from_ransomware_df
from src.models.lstm_model import build_lstm_model

def main():
    csv_path = os.path.join(_project_root, "data", "raw", "irp_logs", "ransomware_combined_dump_feature_distribution.csv")
    df = load_ransomware_irp_dataset(csv_path)

    # Build sequences (this will give only label=1 for now)
    X, y = build_sequences_from_ransomware_df(df, seq_len=10)

    print("X shape:", X.shape)
    print("y shape:", y.shape)
    print("Sample labels:", np.unique(y, return_counts=True))

    # Since all labels=1, training a classifier doesn't make sense yet,
    # but we can still run one training step just to verify code works.
    model = build_lstm_model(input_shape=X.shape[1:])

    es = EarlyStopping(monitor="loss", patience=2, restore_best_weights=True)

    model.fit(
        X,
        y,
        epochs=3,
        batch_size=4,
        callbacks=[es],
    )

    out_dir = os.path.join(_project_root, "data", "processed")
    os.makedirs(out_dir, exist_ok=True)
    model.save(os.path.join(out_dir, "lstm_ransom_only.h5"))
    print("Saved model to data/processed/lstm_ransom_only.h5")

if __name__ == "__main__":
    main()