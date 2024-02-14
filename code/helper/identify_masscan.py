import ipaddress
import struct
import numpy as np
import pandas as pd

# ip_id = dst_addr⊕dst_port⊕tcp_seqnum
def calculate_ipid(dst_addr: str, dst_port: int, tcp_seqnum: int):
    """Note: this function is old and does not use the DST_int already precalculated. Use calculate_ipid_df instead."""

    if pd.notna(dst_addr):
        tcp_seqnum = tcp_seqnum & 0xffff
        ip_int = int(ipaddress.ip_address(dst_addr))
        ip_int = ip_int & 0xffff
        xor_result = ip_int ^ dst_port ^ tcp_seqnum
        return xor_result
    return None

def calculate_masscan_ipid_df(dst_addr_int: pd.Series, dst_port: pd.Series, tcp_seqnum: pd.Series) -> np.ndarray:
    """More efficient ipid calculation that operates on DataFrames.
    Adds a new column `calculated_ipid` to the passed DataFrame
    """

    res = np.where(
        pd.notna(tcp_seqnum) & pd.notna(dst_addr_int),
        np.bitwise_xor(
            np.bitwise_xor(
                np.bitwise_and(dst_addr_int, 0xffff),
                dst_port),
            np.bitwise_and(tcp_seqnum, 0xffff)
        ),
        pd.NA
    )
    return res

if __name__ == "__main__":
    ipid = calculate_ipid("52.67.232.152", 23, 876865688)
    print(ipid)
