import logging
import pandas as pd

def count_and_filter(df_unfiltered: pd.DataFrame, df_filtered: pd.DataFrame, log_message: str):
    count_prev = df_unfiltered.shape[0]
    count_after = df_filtered.shape[0]
    logging.info(f'{log_message}: {count_prev - count_after}')
    # Just return the passed filtered df
    return df_filtered

def filter_instances_data_invalid(df: pd.DataFrame):
    """Filter packets that cause problems in processing and do not cause a large impact on the dataset"""

    # Filter strange ICMP packets (around 500 packets)
    # Most packets among them are ICMP unreachable messages (seemingly) as response to UDP packets
    filtered = count_and_filter(
        df,
        df[~(df['PROTO'].str.contains('ICMP') & df['PROTO'].str.contains(','))],
        'Filtered [ICMP, x] rows'
    )

    # Filter packets without protocol (how can this happen) (around 2 packets)
    filtered = count_and_filter(
        filtered,
        filtered[filtered['PROTO'].notna()],
        'Filtered rows where protocol is None'
    )

    return filtered.reset_index(drop=True)

def filter_instances_data(df: pd.DataFrame):
    """Filter all rows that we don't need for the analysis"""

    # Filter ICMP packets (around 1.4 mio packets)
    filtered = count_and_filter(
        df,
        df[df['PROTO'] != 'ICMP'],
        'Filtered rows where protocol is ICMP'
    )

    # Filter protocols other than TCP and UDP (around 3000 packets)
    filtered = count_and_filter(
        filtered,
        filtered[(filtered['PROTO'] == 'TCP') | (filtered['PROTO'] == 'UDP')],
        'Filtered rows where protocol is not TCP or UDP'
    )

    return filtered.reset_index(drop=True)
