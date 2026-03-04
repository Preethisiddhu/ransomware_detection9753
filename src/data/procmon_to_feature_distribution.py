import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd


@dataclass(frozen=True)
class ProcmonColumns:
    time: str
    operation: str
    path: str
    result: Optional[str] = None


DEFAULT_COLS = ProcmonColumns(
    time="Time of Day",
    operation="Operation",
    path="Path",
    result="Result",
)


def _parse_time_of_day(series: pd.Series) -> pd.Series:
    # Procmon CSV uses "HH:MM:SS.ffffff" (date not included).
    # We anchor to an arbitrary date so we can compute deltas.
    base_date = "1970-01-01 "
    return pd.to_datetime(base_date + series.astype(str), errors="coerce")


def _bin_seconds(timestamps: pd.Series, bin_seconds: int) -> pd.Series:
    t0 = timestamps.min()
    if pd.isna(t0):
        raise ValueError("Could not parse any timestamps from Procmon CSV.")
    delta_s = (timestamps - t0).dt.total_seconds()
    # Convert to 1-based bins in seconds like 5,10,15,...
    return ((delta_s // bin_seconds) + 1) * bin_seconds


def procmon_csv_to_feature_distribution(
    procmon_csv_path: str,
    out_csv_path: str,
    label: int,
    bin_seconds: int = 5,
    cols: ProcmonColumns = DEFAULT_COLS,
) -> pd.DataFrame:
    p = Path(procmon_csv_path)
    if not p.exists():
        raise FileNotFoundError(procmon_csv_path)

    df = pd.read_csv(procmon_csv_path)
    for required in [cols.time, cols.operation, cols.path]:
        if required not in df.columns:
            raise ValueError(
                f"Missing column '{required}' in Procmon CSV. "
                f"Found columns: {list(df.columns)[:20]}"
            )

    ts = _parse_time_of_day(df[cols.time])
    df = df.assign(_ts=ts)
    df = df.dropna(subset=["_ts"])
    if df.empty:
        raise ValueError("After parsing timestamps, no rows remain.")

    df["_bin"] = _bin_seconds(df["_ts"], bin_seconds=bin_seconds).astype(int)

    op = df[cols.operation].astype(str).str.lower()
    is_read = op.str.contains("read")
    is_write = op.str.contains("write")
    is_create = op.str.contains("create") | op.str.contains("open")
    is_setinfo = op.str.contains("setinformation") | op.str.contains("set information")

    # Build numeric features. These are approximations to match the existing model input schema.
    # They keep the same column names as the ransomware feature distribution CSV.
    grouped = df.groupby("_bin", sort=True)
    out = pd.DataFrame(
        {
            "Time": grouped.size().index.astype(int),
            "IRP Operation": grouped.size().values.astype(float),
            "FSF Operation": grouped.apply(lambda g: float(is_read.loc[g.index].sum())).values,
            "FIO Operation": grouped.apply(lambda g: float(is_write.loc[g.index].sum())).values,
            "IRP Flags": 0.0,
            "IRP Major Opn": grouped.apply(lambda g: float(is_create.loc[g.index].sum())).values,
            "IRP Minor Opn": grouped.apply(lambda g: float(is_setinfo.loc[g.index].sum())).values,
            "IRP Status": 0.0,
            "File Object": grouped[cols.path].nunique(dropna=True).values.astype(float),
            "File Accesed": grouped[cols.path].nunique(dropna=True).values.astype(float),
            "Buffer Length": 0.0,
            "Entropy": 0.0,
        }
    )

    # Optional: if Result column exists, estimate "success ratio" into IRP Status.
    if cols.result and cols.result in df.columns:
        res = df[cols.result].astype(str).str.lower()
        is_success = res.isin(["success", "ok"])
        out["IRP Status"] = grouped.apply(
            lambda g: float(is_success.loc[g.index].mean()) if len(g.index) else 0.0
        ).values

    out["label"] = int(label)
    Path(out_csv_path).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_csv_path, index=False)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a Procmon CSV into the project's feature_distribution CSV format."
    )
    parser.add_argument("--in", dest="in_csv", required=True, help="Procmon CSV input path")
    parser.add_argument("--out", dest="out_csv", required=True, help="Output CSV path")
    parser.add_argument(
        "--label",
        type=int,
        default=0,
        help="Label to assign (0=benign, 1=ransomware). Default: 0",
    )
    parser.add_argument(
        "--bin-seconds",
        type=int,
        default=5,
        help="Time bin size in seconds. Default: 5",
    )
    args = parser.parse_args()

    procmon_csv_to_feature_distribution(
        procmon_csv_path=args.in_csv,
        out_csv_path=args.out_csv,
        label=args.label,
        bin_seconds=args.bin_seconds,
    )
    print(f"Saved: {args.out_csv}")


if __name__ == "__main__":
    main()

