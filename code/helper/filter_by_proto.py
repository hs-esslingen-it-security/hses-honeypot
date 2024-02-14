import pandas as pd

def filter_iot_scans(df: pd.DataFrame) -> pd.DataFrame:
    """Returns all packets that match the observed IoT ports"""

    return df[(df['DPT'] == 4840)|(df['DPT'] == 1883)|(df['DPT'] == 5672)|(df['DPT'] == 5683)]

def filter_amqp_scans(df: pd.DataFrame) -> pd.DataFrame:
    """Returns all packets that match the AMQP port"""

    return df[df['DPT'] == 5672]

def filter_coap_scans(df: pd.DataFrame) -> pd.DataFrame:
    """Returns all packets that match the CoAP port"""

    return df[df['DPT'] == 5683]

def filter_mqtt_scans(df: pd.DataFrame) -> pd.DataFrame:
    """Returns all packets that match the MQTT port"""

    return df[df['DPT'] == 1883]

def filter_opcua_scans(df: pd.DataFrame) -> pd.DataFrame:
    """Returns all packets that match the OPC UA port"""

    return df[df['DPT'] == 4840]
