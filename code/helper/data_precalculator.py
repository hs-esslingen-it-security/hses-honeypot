import logging
import ipaddress
import pandas as pd
import numpy as np

from helper.options_parser_and_signature_matching import decode_tcp_options
from helper.identify_masscan import calculate_ipid, calculate_masscan_ipid_df

"""
Analyzes logs and precalculates information, like parsing TCP options and calculating the IPID
"""

def prepare_tcp_flags(df: pd.DataFrame) -> pd.Series:
    # empty tcp_flags fields to nan
    tcp_flags = df['TCP_Flags'].replace('', np.nan)
    return tcp_flags

def extract_tcp_flags(df: pd.DataFrame) -> None:
    """Extract each flag from the TCP_Flags string into its own column with a True/False value"""
    df['tcp_flags_cwr'] = np.where(df['TCP_Flags'].fillna('').str.contains('CWR'), True, False)
    df['tcp_flags_ece'] = np.where(df['TCP_Flags'].fillna('').str.contains('ECE'), True, False)
    df['tcp_flags_urg'] = np.where(df['TCP_Flags'].fillna('').str.contains('URG'), True, False)
    df['tcp_flags_ack'] = np.where(df['TCP_Flags'].fillna('').str.contains('ACK'), True, False)
    df['tcp_flags_psh'] = np.where(df['TCP_Flags'].fillna('').str.contains('PSH'), True, False)
    df['tcp_flags_rst'] = np.where(df['TCP_Flags'].fillna('').str.contains('RST'), True, False)
    df['tcp_flags_syn'] = np.where(df['TCP_Flags'].fillna('').str.contains('SYN'), True, False)
    df['tcp_flags_fin'] = np.where(df['TCP_Flags'].fillna('').str.contains('FIN'), True, False)

def analyze_tcp_options(df: pd.DataFrame) -> None:
    """Parses and analyzes TCP options and writes them to new columns of the df"""

    # Parse TCP options
    parsed_options = df['TCP_Options'] \
    .apply(
        lambda opt: decode_tcp_options(opt) if pd.notna(opt) else pd.NA
    )

    parsed_options = pd.json_normalize(parsed_options)

    # Extract maximum segment size from parsed TCP options
    mss = parsed_options['Maximum Segment Size'] \
        .apply(
            lambda mss_str: int(mss_str, base=16) if pd.notna(mss_str) else pd.NA
        ) \
        .astype('Int16')

    df['tcp_options_window_scale'] = parsed_options['Window Scale']
    df['tcp_options_sack_permitted'] = parsed_options['SACK Permitted']
    df['tcp_options_sack'] = parsed_options['SACK'] if 'SACK' in parsed_options else ''
    df['tcp_options_timestamps'] = parsed_options['Timestamps']
    df['tcp_options_mss'] = mss

def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))

def precalculate_data(df: pd.DataFrame) -> None:
    df['id_cleaned'] = np.where(
        pd.notna(df['ID']),
        df['ID'],
        pd.NA
    )
    df['id_cleaned'] = df['id_cleaned'].astype('UInt16')

    df['TCP_Flags'] = prepare_tcp_flags(df)

    extract_tcp_flags(df)

    logging.info('Analyzing TCP options')
    analyze_tcp_options(df)

    # Convert destiantion IP to integer
    logging.info('Converting destination IPs to integer')
    df['DST_int'] = df['DST'].apply(lambda dst: ip_to_int(dst))
    df['DST_int'] = df['DST_int'].astype('Int64')

    # Convert source IP to integer
    logging.info('Converting source IPs to integer')
    df['SRC_int'] = df['SRC'].apply(lambda src: ip_to_int(src))

    logging.info('Calculating masscan IPIDs')
    df['calculated_ipid_masscan'] = calculate_masscan_ipid_df(
        df['DST_int'],
        df['DPT'],
        df['SEQ']
    )
