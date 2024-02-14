import os
import logging
import numpy as np
import pandas as pd
from helper.check_tools_one_df import check_tools_one_df
from helper.organization_matcher import find_potentially_orgas, identify_organizations, manual_tool_identification_fixes
from helper.filter import filter_instances_data, filter_instances_data_invalid
from helper.data_precalculator import precalculate_data

CSV_IN_PATH = './data/20240131_demo'
CSV_OUT_PATH = './data/20240131_demo'
# Name if the files without file extension
IN_NAME = 'data_raw'
OUT_NAME = 'data_processed'

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

    # Filter invalid/problematic data
    logging.info('Filtering invalid/problematic rows from instance data')
    df = filter_instances_data_invalid(df)

    df = df.convert_dtypes()
    
    df['@timestamp_x'] = pd.to_datetime(df['@timestamp_x'])
    df = df.sort_values(by=['@timestamp_x']).reset_index(drop=True)
    logging.info(f'Number of packets: {df.shape[0]}')

    # Prevent NA errors by setting default values
    df['company.name'] = np.where(df['company.name'].isnull, ' ', df['company.name'])
    df['company.domain'] = np.where(df['company.domain'].isnull, ' ', df['company.domain'])
    df['asn.name'] = np.where(df['asn.name'].isnull, ' ', df['asn.name'])
    df['asn.asn'] = np.where(df['asn.asn'].isnull, ' ', df['asn.asn'])
    df['asn.domain'] = np.where(df['asn.domain'].isnull, ' ', df['asn.domain'])
    df['hostname'] = np.where(df['hostname'].isnull, ' ', df['hostname'])

    logging.info('Precalculating data')
    precalculate_data(df)

    logging.info('Identifying tools')
    ### Identify tools and add them to the df STEP2
    one_frame = check_tools_one_df(df)
    
    ### All steps before are not necessary if the ALL_merged-with-Tools-Info contains the current information STEP3
    logging.info('Identifying organizations')
    one_frame_identified = identify_organizations(one_frame)

    logging.info('Applying manual fixes of identified tools for some organizations')
    manual_tool_identification_fixes(one_frame_identified)

    # Filter unwanted data
    logging.info('Filtering unwanted rows from instance data')
    one_frame_identified = filter_instances_data(one_frame_identified)

    logging.info('Saving fitered CSV')
    one_frame_identified.to_csv(
        os.path.join(CSV_OUT_PATH, f'{OUT_NAME}.csv'),
        encoding='utf-8',
        index=False
    )

    logging.info('Finished')
