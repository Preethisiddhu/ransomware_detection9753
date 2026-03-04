import os
import numpy as np
from tensorflow.keras.callbacks import EarlyStopping
from src.data.load_irp_dataset import load_mixed_irp_dataset, load_ransomware_irp_dataset
from src.data.build_sequences import build_sequences_from_ransomware_df
from src.models.lstm_model import build_lstm_model

def main():
    csv_path = "data/raw/irp_logs/ransomware_combined_dump_feature_distribution.csv"
    benign_csv_path = "data/raw/irp_logs/benign_combined_dump_feature_distribution.csv"

    if os.path.exists(benign_csv_path):
        print(f"Found benign dataset: {benign_csv_path}")
        df = load_mixed_irp_dataset(csv_path, benign_csv_path)
    else:
        print(
            "Benign dataset not found. Training will run in ransomware-only sanity-check mode.\n"
            f"To enable proper training, add: {benign_csv_path}"
        )
        df = load_ransomware_irp_dataset(csv_path)

    # Build sequences (this will give only label=1 for now)
    X, y = build_sequences_from_ransomware_df(df, seq_len=10)

    print("X shape:", X.shape)
    print("y shape:", y.shape)
    print("Sample labels:", np.unique(y, return_counts=True))

    # Note: If df has only label=1, this is just a code sanity check.
    model = build_lstm_model(input_shape=X.shape[1:])

    es = EarlyStopping(monitor="loss", patience=2, restore_best_weights=True)

    model.fit(
        X,
        y,
        epochs=3,
        batch_size=4,
        callbacks=[es],
    )

    os.makedirs("data/processed", exist_ok=True)
    model.save("data/processed/lstm_ransom_only.keras")
    print("Saved model to data/processed/lstm_ransom_only.keras")

   
if __name__ == "__main__":
    main()