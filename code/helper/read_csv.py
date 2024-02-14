import pandas as pd
import enum

def read_processed_csv(path: str) -> pd.DataFrame:
    """Read merged CSV with orgas and convert some columns into the correct format to prevent errors
    during later processing
    """

    df = pd.read_csv(path, engine="pyarrow", dtype={
        # Setting the type for some selected fields so that they are converted correctly and no errors occur when comparing values
        'SEQ': 'UInt32',
        'ID': 'UInt16',
        'WINDOW': 'UInt16',
        'DPT': 'UInt16',
        'id_cleaned': 'UInt16',
        'tcp_options_mss': 'UInt16',
        'DST_int': 'UInt32',
        'calculated_ipid_masscan': 'UInt16'
    })
    return df


class Instance(enum.Enum):
    London = 0
    Mumbai = 1
    Tokyo = 2
    SaoPaulo = 3
    CapeTown = 4
    NorthernCalifornia = 5