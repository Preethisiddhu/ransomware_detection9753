import os
import pandas as pd

def _coerce_numeric(df: pd.DataFrame) -> pd.DataFrame:
    if "Time" in df.columns:
        df["Time"] = pd.to_numeric(df["Time"], errors="coerce")
    if "Buffer Length" in df.columns:
        df["Buffer Length"] = pd.to_numeric(df["Buffer Length"], errors="coerce")
    if "Entropy" in df.columns:
        df["Entropy"] = pd.to_numeric(df["Entropy"], errors="coerce")
    return df


def load_irp_dataset(csv_path: str, label: int) -> pd.DataFrame:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(csv_path)

    df = pd.read_csv(csv_path)
    df = _coerce_numeric(df)
    df["label"] = int(label)
    return df


def load_ransomware_irp_dataset(csv_path: str) -> pd.DataFrame:
    """
    Load the ransomware_combined_dump_feature_distribution.csv file
    and return a pandas DataFrame.
    """
    return load_irp_dataset(csv_path=csv_path, label=1)


def load_mixed_irp_dataset(
    ransomware_csv_path: str,
    benign_csv_path: str,
) -> pd.DataFrame:
    ransom_df = load_irp_dataset(ransomware_csv_path, label=1)
    benign_df = load_irp_dataset(benign_csv_path, label=0)

    # Align columns (in case one side has extra cols)
    all_cols = sorted(set(ransom_df.columns) | set(benign_df.columns))
    ransom_df = ransom_df.reindex(columns=all_cols)
    benign_df = benign_df.reindex(columns=all_cols)

    return pd.concat([ransom_df, benign_df], ignore_index=True)