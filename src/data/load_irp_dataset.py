import os
import pandas as pd

def load_ransomware_irp_dataset(csv_path: str) -> pd.DataFrame:
    """
    Load the ransomware_combined_dump_feature_distribution.csv file
    and return a pandas DataFrame.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(csv_path)

    df = pd.read_csv(csv_path)

    # Expecting columns:
    # Time, IRP Operation, FSF Operation, FIO Operation, IRP Flags,
    # IRP Major Opn, IRP Minor Opn, IRP Status, File Object, File Accesed,
    # Buffer Length, Entropy

    # Clean simple things
    df["Time"] = pd.to_numeric(df["Time"], errors="coerce")
    df["Buffer Length"] = pd.to_numeric(df["Buffer Length"], errors="coerce")
    df["Entropy"] = pd.to_numeric(df["Entropy"], errors="coerce")

    # For now, add a dummy label column = 1 (ransomware)
    # Later you should merge with benign data and adjust labels
    df["label"] = 1

    return df