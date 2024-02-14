import ipaddress
import numpy as np
import pandas
import pandas as pd
from matplotlib import pyplot as plt
from helper.identify_masscan import calculate_ipid, calculate_masscan_ipid_df

pd.options.mode.chained_assignment = None 

def check_tools_one_df_prepare(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare everything to determine tools"""
    only_with_seq = df.copy()
    only_with_seq['SEQ'] = only_with_seq['SEQ'].astype('Int64')
    only_with_seq["tool"] = pd.NA
    return only_with_seq

##### Scanning Tools
def detect_nmap(only_with_seq: pd.DataFrame) -> np.ndarray:
    res = np.where(
        (
            # -PS, -sS/-F
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['WINDOW'] == 1024) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 1460) &
            (only_with_seq['ACK'] == 0)
        ) |
        (
            # -PA, -sA/-sW
            (only_with_seq['tcp_flags_ack']) &
            (only_with_seq['WINDOW'] == 1024) &
            (only_with_seq['tcp_options_mss'].isna()) &
            (only_with_seq['PROTO'] == 'TCP') &
            (only_with_seq['SEQ'] == 0)
        ) |
        (
            # -sT
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['WINDOW'] == 64240) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 1460) &
            (only_with_seq['ACK'] == 0)
        ) |
        (
            # -sN
            (only_with_seq['PROTO'] == 'TCP') &
            (only_with_seq['TCP_Flags'].isna()) &
            (only_with_seq['WINDOW'] == 1024) &
            (only_with_seq['tcp_options_mss'].isna()) &
            (only_with_seq['ACK'] == 0)
        ) |
        (
            # -sF/-sX
            (only_with_seq['tcp_flags_psh']) &
            (only_with_seq['tcp_flags_urg']) &
            (only_with_seq['tcp_flags_fin']) &
            (only_with_seq['WINDOW'] == 1024) &
            (only_with_seq['tcp_options_mss'].isna()) &
            (only_with_seq['ACK'] == 0)
        ) |
        (
            # -sM
            (only_with_seq['tcp_flags_fin']) &
            (only_with_seq['tcp_flags_ack']) &
            (only_with_seq['WINDOW'] == 1024) &
            (only_with_seq['tcp_options_mss'].isna()) &
            (only_with_seq['SEQ'] == 0)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['WINDOW'] == 1) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 1460)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['WINDOW'] == 63) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 1400)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['WINDOW'] == 4) &
            (only_with_seq['tcp_options_mss'].isna())
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['WINDOW'] == 16) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 536)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['WINDOW'] == 512) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 265)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['tcp_flags_ece']) &
            (only_with_seq['tcp_flags_cwr']) &
            (only_with_seq['WINDOW'] == 3) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 1460) &
            (only_with_seq['ACK'] == 0)
        ) |
        (
            # -O
            (only_with_seq['PROTO'] == 'TCP') &
            (only_with_seq['TCP_Flags'].isna()) &
            (only_with_seq['WINDOW'] == 128) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 265)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_fin']) &
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['tcp_flags_psh']) &
            (only_with_seq['tcp_flags_urg']) &
            (only_with_seq['WINDOW'] == 256) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 265)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_ack']) &
            (only_with_seq['WINDOW'] == 1024) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 265)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_syn']) &
            (only_with_seq['WINDOW'] == 31337) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 265)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_ack']) &
            (only_with_seq['WINDOW'] == 32768) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 265)
        ) |
        (
            # -O
            (only_with_seq['tcp_flags_fin']) &
            (only_with_seq['tcp_flags_psh']) &
            (only_with_seq['tcp_flags_urg']) &
            (only_with_seq['WINDOW'] == 65535) &
            (only_with_seq['tcp_options_mss'].fillna(0) == 265)
        ),
        True,
        False
    )

    return res

def detect_zmap(only_with_seq: pd.DataFrame) -> np.ndarray:
    # zmap
    res = np.where(
        pd.notna(only_with_seq["id_cleaned"]) &
        (only_with_seq["id_cleaned"].fillna(0) == 54321),
        True,
        False
    )
    
    return res

def detect_masscan(only_with_seq: pd.DataFrame) -> np.ndarray:
    # masscan
    res = np.where(
        pd.notna(only_with_seq["id_cleaned"]) &
        pd.notna(only_with_seq["calculated_ipid_masscan"]) &
        # Use fillna to prevent comparison errors with pd.NA
        (only_with_seq["id_cleaned"].fillna(0) == only_with_seq["calculated_ipid_masscan"].fillna(0)),
        True,
        False
    )
    
    return res

def detect_unicorn(only_with_seq: pd.DataFrame) -> pd.DataFrame:
    # unicorn
    potential_unicorn_session_keys = pd.Series(
        np.bitwise_xor.reduce((
            only_with_seq['SEQ'].fillna(0),
            only_with_seq['SRC_int'],
            (np.left_shift(only_with_seq['SPT'].fillna(0), 16) + only_with_seq['DPT'].fillna(0))
        )),
        index=only_with_seq.index
    )

    # Invalidate all session keys where the sequence number is NA
    potential_unicorn_session_keys = pd.Series(
        np.where(
            pd.isna(only_with_seq['SEQ']) |
            pd.isna(only_with_seq['SPT']) |
            pd.isna(only_with_seq['DPT']),
            pd.NA,
            potential_unicorn_session_keys
        ),
        index=only_with_seq.index
    )

    # Important: here we determine how many occurrences of the same session key in the dataset are needed
    # to consider a packet to be sent by unicorn
    potential_session_keys_grouped = potential_unicorn_session_keys \
        .groupby([potential_unicorn_session_keys]).transform('count') > 150
    
    res = np.where(
        potential_session_keys_grouped == True,
        True,
        False
    )

    return res

##### Botnets
def detect_hajime(only_with_seq: pd.DataFrame) -> np.ndarray:
    """Hajime detection does not make sense because there are almost no matches
    and those who match are most likely false positives
    """
    # hajime
    res = np.where(
        pd.notna(only_with_seq['WINDOW']) &
        pd.notna(only_with_seq['SEQ']) &
        (only_with_seq['WINDOW'].fillna(0) == 14600) &
        (
            (np.bitwise_and(only_with_seq['SEQ'].fillna(0), 0xff) == 0) |
            (np.bitwise_and(only_with_seq['SEQ'].fillna(0), 0xff000000) == 0)
        ),
        True,
        False
    )

    return res

def detect_mirai(only_with_seq: pd.DataFrame) -> np.ndarray:
    res = np.where(
        pd.notna(only_with_seq['SEQ']) &
        pd.notna(only_with_seq['DST_int']) &
        (np.bitwise_xor(only_with_seq['SEQ'].fillna(0), only_with_seq['DST_int'].fillna(0)) == 0) &
        ((only_with_seq['DPT'].fillna(0) == 23) | (only_with_seq['DPT'].fillna(0) == 2323)),
        True,
        False
    )
    
    return res

##### Other
def detect_other(only_with_seq: pd.DataFrame) -> np.ndarray:
    """Just replaces na with 'other' string"""

    # Other
    res = np.where(
        only_with_seq["tool"].isna(),
        "other", only_with_seq['tool'])
    
    return res

def create_tools_column(df: pd.DataFrame) -> np.ndarray:
    res = pd.Series(np.full(df.shape[0], 'other'))

    res = np.where(
        df['tool_nmap'] == True,
        'nmap',
        'other'
    )

    res = np.where(
        df['tool_zmap'] == True,
        'zmap',
        res
    )

    res = np.where(
        df['tool_masscan'] == True,
        'masscan',
        res
    )

    res = np.where(
        df['tool_mirai'] == True,
        'mirai',
        res
    )

    res = np.where(
        df['tool_unicorn'] == True,
        'unicorn',
        res
    )

    return res

def check_tools_one_df(df: pd.DataFrame) -> pd.DataFrame:
    """All-in-one function to determine tools"""

    only_with_seq = check_tools_one_df_prepare(df)
    only_with_seq['tool_nmap'] = detect_nmap(only_with_seq)
    only_with_seq['tool_zmap'] = detect_zmap(only_with_seq)
    only_with_seq['tool_masscan'] = detect_masscan(only_with_seq)
    only_with_seq['tool_mirai'] = detect_mirai(only_with_seq)
    only_with_seq['tool_unicorn'] = detect_unicorn(only_with_seq)
    only_with_seq['tool'] = create_tools_column(only_with_seq)
    return only_with_seq


