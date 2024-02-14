import os
import logging
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as tck
from matplotlib import pyplot as plt

from helper.read_csv import read_processed_csv, Instance
from helper.fft import calculate_fft
from helper.filter_by_proto import filter_amqp_scans, filter_coap_scans, filter_mqtt_scans, filter_opcua_scans

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logging.info('Loading the data ...')

DATA_FOLDER = './data/20240131_demo/'
one_frame = read_processed_csv(os.path.join(DATA_FOLDER, 'data.csv'))

SAVE_FIGURES = False

# Define Eval to execute
EXECUTE_FFT = True

### FFT
if EXECUTE_FFT:
    logging.info('Starting the FFT Eval')

    orgas_group = one_frame.groupby('organization', dropna=True)

    fft_results = {}

    filtered_df = None
    for orga_name, orga_df in orgas_group:
        orga_df.loc[:, 'iot_proto'] = 'Other'

        orga_df.loc[
            orga_df.index.isin(filter_amqp_scans(orga_df).index),
            'iot_proto'
        ] = 'AMQP'

        orga_df.loc[
            orga_df.index.isin(filter_coap_scans(orga_df).index),
            'iot_proto'
        ] = 'CoAP'

        orga_df.loc[
            orga_df.index.isin(filter_mqtt_scans(orga_df).index),
            'iot_proto'
        ] = 'MQTT'

        orga_df.loc[
            orga_df.index.isin(filter_opcua_scans(orga_df).index),
            'iot_proto'
        ] = 'OPC UA'

        filtered_df = orga_df[orga_df['instance_id'] == Instance.London.value]
        if len(filtered_df) == 0:
            continue

        logging.info(f'  Organization: {orga_name}')
        fft_results[orga_name] = {}

        if filtered_df is not None and filtered_df.shape[0] > 0:
            for iot_proto in ["Other", "AMQP", "CoAP", "MQTT", "OPC UA"]:
                df = filtered_df.query(f'iot_proto == "{iot_proto}"')
                if len(df) == 0:
                    continue

                logging.info(f'   +-- Protocol Group: {iot_proto}')
                fft_results[orga_name][iot_proto] = {}

                top_port_dfs = [df]
                if iot_proto == "Other":
                    df_tmp_1 = df.take([5], axis=1)
                    ports = df_tmp_1.value_counts()

                    for idx, port in enumerate(ports.index):
                        df_tmp_2 = df.query(f'DPT == {ports.index[idx]}')
                        if len(df_tmp_2) != 0:
                            top_port_dfs.append(df_tmp_2)
                        if idx >= 1:
                            continue
                
                for idx, top_port_df in enumerate(top_port_dfs):
                    N, X, freqs, day, spots = calculate_fft(top_port_df)

                    if SAVE_FIGURES:
                        fig, axes = plt.subplots(figsize=(15,3), ncols=2)
                        ax=axes[0]
                        ax.plot(day, spots)
                        ax.xaxis.set_major_locator(tck.MultipleLocator(50))

                        ax=axes[1]
                        extent = 50#N
                        ax.set_xlabel(f'period [days] -- {iot_proto} ({orga_name})')
                        ax.stem(freqs[:extent], abs(X[:extent]))
                        ticks = ax.get_xticks()
                        ax.set_xticklabels([f'{1/tick:.1f}' if tick!=0 else '$\infty$' for tick in ticks])
                        ax.invert_xaxis()
                        ax.grid()
                        fig.tight_layout()
                        fig.savefig(os.path.join(DATA_FOLDER, f'results/fft/{orga_name}-{iot_proto}-{idx}.pdf'), bbox_inches='tight')

                    fft_results[orga_name][iot_proto][f'{idx}-freq-1-pos'] = freqs[list(abs(X)).index(sorted(abs(X))[-1])]
                    fft_results[orga_name][iot_proto][f'{idx}-freq-1-val'] = sorted(abs(X))[-1]
                    fft_results[orga_name][iot_proto][f'{idx}-freq-2-pos'] = freqs[list(abs(X)).index(sorted(abs(X))[-2])]
                    fft_results[orga_name][iot_proto][f'{idx}-freq-2-val'] = sorted(abs(X))[-2]

    count_periodic = [0, 0, 0, 0, 0]
    orgs_periodic = []
    count_continuous = [0, 0, 0, 0, 0]
    orgs_continuous = []
    count_acyclic = [0, 0, 0, 0, 0]
    orgs_acyclic = []
    count_sporadic = [0, 0, 0, 0, 0]
    orgs_sporadic = []
    periods = []

    for orga_name in fft_results:
        for idx, iot_proto in enumerate(["Other", "AMQP", "CoAP", "MQTT", "OPC UA"]):
            if iot_proto not in fft_results[orga_name]:
                continue

            results = []
            for port_idx in range(0,5):
                if f'{port_idx}-freq-1-val' not in fft_results[orga_name][iot_proto]:
                    break
                
                if fft_results[orga_name][iot_proto][f'{port_idx}-freq-1-pos'] == 0.0:
                    sub_port_idx = "2"
                else:
                    sub_port_idx = "1"

                freq = 1/fft_results[orga_name][iot_proto][f'{port_idx}-freq-{sub_port_idx}-pos']
                value1 = fft_results[orga_name][iot_proto][f'{port_idx}-freq-1-val']
                value2 = fft_results[orga_name][iot_proto][f'{port_idx}-freq-2-val']

                freq_strength = value1 / value2

                if value1 < 0.05:
                    results.append(("sporadic", freq))

                elif freq_strength > 3:
                    if sub_port_idx == "1":
                        results.append(("periodic", freq))
                    else:
                        results.append(("continuous", 0))
                    
                elif freq_strength > 1.5:
                    results.append(("periodic", freq))

                else:
                    results.append(("acyclic", 0))

            if len(results) == 0:
                continue

            last_was_periodic = False
            for sub_res in results:
                last_was_periodic = False
                if sub_res[0] == "acyclic":
                    count_acyclic[idx] += 1
                    break
                if sub_res[0] == "sporadic":
                    count_acyclic[idx] += 1
                    break
                if sub_res[0] == "continuous":
                    count_continuous[idx] += 1
                    count_periodic[idx] += 1
                    break
                if sub_res[0] == "periodic":
                    last_was_periodic = True

            if last_was_periodic:
                count_periodic[idx] += 1

    print("------------------------------------------\nperiodic:")
    print(count_periodic)
    print(orgs_periodic)
    print("------------------------------------------\ncontinuous:")
    print(count_continuous)
    print(orgs_continuous)
    print("------------------------------------------\nacyclic:")
    print(count_acyclic)
    print(orgs_acyclic)
    print("------------------------------------------\nsporadic:")
    print(count_sporadic)
    print(orgs_sporadic)

    print("------------------------------------------\nintervals:")
    print(periods)