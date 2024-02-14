import os
import logging
import numpy as np
import pandas as pd
import random

CSV_IN_PATH = '../data/20240131_demo'
CSV_OUT_PATH = '../data/20240131_demo'
# Name if the files without file extension
IN_NAME = 'data'
OUT_NAME = 'data_raw'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

if __name__ == "__main__":
    logging.info('Reading CSV')
    df = pd.read_csv(
        os.path.join(CSV_IN_PATH, f'{IN_NAME}.csv'),
        engine="pyarrow"
    )

    logging.info('Randomizing Source IPs')
    unique_ips = df['ip'].unique()
    for ip in unique_ips:
        new_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        df['ip'] = np.where(df['ip'] == ip, new_ip, df['ip'])
        df['SRC'] = np.where(df['SRC'] == ip, new_ip, df['SRC'])

    logging.info('Randomizing Destination IPs')
    unique_ips = df['DST'].unique()
    for ip in unique_ips:
        new_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        df['DST'] = np.where(df['DST'] == ip, new_ip, df['DST'])

    logging.info('Deleting unnecessary iptables columns')
    for field in ['IN', 'SRC_MAC', 'DST_MAC', 'message']:
        df[field] = ''

    logging.info('Deleting ipinfo columns')
    for field in ['hostname', 'city', 'postal', 'loc', 'country', '@timestamp_y',
                  'company.domain', 'company.type', 'company.name', 'privacy.service', 'privacy.vpn', 'privacy.tor', 'privacy.hosting',
                  'privacy.relay', 'privacy.proxy', 'domains.total', 'domains.domains', 'asn.domain', 'asn.route', 'asn.type', 'asn.asn',
                  'asn.name', 'domains.ip', 'anycast', 'bogon', 'domains.page']:
        df[field] = ''

    logging.info('Deleting calculated columns (see import-data.py)')
    for field in ['id_cleaned', 'tcp_flags_cwr', 'tcp_flags_ece', 'tcp_flags_urg',
                  'tcp_flags_ack', 'tcp_flags_psh', 'tcp_flags_rst', 'tcp_flags_syn', 'tcp_flags_fin', 'tcp_options_window_scale',
                  'tcp_options_sack_permitted', 'tcp_options_sack', 'tcp_options_timestamps', 'tcp_options_mss', 'DST_int', 'SRC_int',
                  'calculated_ipid_masscan']:
        df[field] = ''

    logging.info('Deleting categorized columns (see import-data.py)')
    for field in ['tool', 'tool_nmap', 'tool_zmap', 'tool_masscan', 'tool_mirai', 'tool_unicorn', 'organization',
                  'organization_short', 'organization_label', 'hosting_organization']:
        df[field] = ''

    logging.info('Saving fitered CSV')
    df.to_csv(
        os.path.join(CSV_OUT_PATH, f'{OUT_NAME}.csv'),
        encoding='utf-8',
        index=False
    )

    logging.info('Finished')
