import numpy as np
from tensorflow.keras.models import load_model
from src.data.load_irp_dataset import load_ransomware_irp_dataset
from src.data.build_sequences import build_sequences_from_ransomware_df

def main():
    csv_path = "data/raw/irp_logs/ransomware_combined_dump_feature_distribution.csv"
    df = load_ransomware_irp_dataset(csv_path)
    X, y = build_sequences_from_ransomware_df(df, seq_len=10)

    print("X shape:", X.shape)
    model = load_model("data/processed/lstm_ransom_only.keras")

    # first few sequences-ku prediction
    preds = model.predict(X[:5])
    print("Raw predictions:", preds)
    print("True labels   :", y[:5])

if __name__ == "__main__":
    main()