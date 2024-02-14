from collections import OrderedDict
from typing import *

import pandas as pd
import re

tcp_option_types = {'00': {"name": "End of Option List", "length": 0},
                    '01': {"name": "No-Operation", "length": 0},
                    '02': {"name": "Maximum Segment Size", "length": 4},
                    '03': {"name": "Window Scale", "length": 3},
                    '04': {"name": "SACK Permitted", "length": 2},
                    '05': {"name": "SACK", "length": 24},
                    '08': {"name": "Timestamps", "length": 10},
                    }

def iterate_over_loglines(df: pd.DataFrame):
    debug_counter = 0
    signatures = read_in_p0f_db("p0f.fp")
    matches_set = set()
    label_set = set()
    for row in df.itertuples():

        option_hex = getattr(row, "TCP_Options", "")

        ip_version = getattr(row, 'IP_Version', "iptables4")

        if ip_version == "iptables4":
            ip_version = 4
        if ip_version == "iptables6":
            ip_version = 6

        ttl = getattr(row, 'TTL')
        # IP options, usually zero for normal IPv4 traffic
        olen = 0

        # only available if specified in options; is there an default value to use? 1460 or 536
        # seems to be 0 if we look at p0f db
        # same for scale
        mss = 0
        scale = 0
        olayout = ""
        if option_hex:
            options = decode_tcp_options(option_hex)
            # 0 seems to be default in p0f db if mss is missing in options
            mss = options.get("Maximum Segment Size", 0)

            # hex to decimal
            mss = hex_to_decimal(str(mss))

            # this is set to 0 when Option is not set
            scale = options.get("Window Scale", 0)
            scale = hex_to_decimal(str(scale))

            olayout = create_olayout(options)

        wsize = getattr(row, 'WINDOW')

        quirks = get_quirks(row)

        # payload size, normally we have no payloads
        pclass = 0

        sig_parts = [ip_version, ttl, olen, mss, f"{wsize},{scale}", olayout, quirks, pclass]

        conn_string_in_p0f_format = ':'.join(str(x) for x in sig_parts)

        # print(conn_string_in_p0f_format)
        matches, matches_dict_list = match_with_sig_db(conn_string_in_p0f_format, signatures, mss, ttl, option_hex)
        if matches:
            #if len(matches) > 1:
                #print(f"{len(matches)} signatures matched")
            # print("\n")
            # needs .at to add list to cell
            # print(f"Optionshex: {option_hex}")
            df.at[row.Index, 'signature'] = matches
            # debug_counter += 1
            label_set.update(matches)
        if matches_dict_list:
            for m in matches_dict_list:
                # transform to set for deduplicate
                matches_set.add(frozenset(m.items()))

        # if debug_counter > 2000:
        #     print(df.head(100).to_markdown())
        #     return
    # print(df.to_markdown())
    myUniqueSet = [dict(s) for s in matches_set]
    print(f"Unique Options matches: {myUniqueSet}")
    print("---")
    print(f"Unique matche Labels: {label_set}")
    return df


def match_with_sig_db(conn_string: str, signatures: Dict[str, List[str]], mss_val: int, ttl_val: int,
                      option_hex: str) -> (List[str], list[Dict]):
    matches = []
    matches_dict = []

    for label, values in signatures.items():
        for sig in values:
            regex = sanitize_sig_for_regex(sig, mss_val, ttl_val)
            matched_string = re.search(regex, conn_string)
            if matched_string:
                matches.append(label)
                match = {
                    "label": label,
                    "signature": sig,
                    "through sanitized version": regex,
                    "original_conn_string": matched_string.string,
                    "option_hex": option_hex
                }
                matches_dict.append(match)

    return matches, matches_dict


# '%8192' atm never occures
# 'mtu*xx' only occures 1x atm
# for now replace 'mtu*' with *
def sanitize_sig_for_regex(signature: str, mss: int, real_ttl: int) -> str:
    """
       exceptions to remove:
       ttl: 64- --> max intial ttl and Randomized
       wsize: allows notation such as 'mss*4', 'mtu*4', or '%8192'
                  to be used. Wilcard ('*') is possible too.

       """

    if "mss*" in signature:
        multiplicand = re.search(r"mss\*(\d*)", signature).group(1)
        wsize_calc = mss * int(multiplicand)
        signature = re.sub(r"mss\*\d*", str(wsize_calc), signature)

    if "mtu*" in signature:
        signature = re.sub(r"mtu\*\d*", "*", signature)

    # this is to remove ttl- value : e.g. 20-
    # signature = re.sub(r"\d*-", "*", signature)

    # get ttl value -> ttl starts after first ':'
    x = signature.find(":")
    y = signature.find(":", x + 1)

    initial_ttl = signature[x + 1:y]

    # this is to remove ttl- value : e.g. 20- ; allow ttl difference up to 30
    max_ttl_difference = 30
    init_ttl_sanitized = int(initial_ttl.replace("-", ""))
    if "-" in initial_ttl or "*" in initial_ttl or (max_ttl_difference > (init_ttl_sanitized - real_ttl) > 0):
        replacement = "*"
        signature = signature[:x + 1] + replacement + signature[y:]
    else:
        # leave ttl unchanged so regex will not match
        pass

    # replace * with .* , escape + and ?
    signature = re.sub(r"\*", ".*", signature)
    signature = signature.replace("+", r"\+")
    signature = signature.replace("?", r"\?")

    return signature


def read_in_p0f_db(path: str) -> Dict[str, List[str]]:
    signature_dict = {}

    with open(path) as file:

        line = file.readline()

        # go to syn signature area
        while True:
            if line.strip() == "; TCP SYN signatures":
                break
            line = file.readline()

        # read in sigs till HTTP client signatures
        line = file.readline()
        while line:
            if line.strip() == "; HTTP client signatures":
                break

            if line.strip().startswith("label"):
                label = line[8:].strip()
                sig_list = []

                innerline = file.readline()
                while innerline:
                    if innerline.strip() == "":
                        break
                    if innerline.startswith("sig"):
                        sig = innerline[8:].strip()
                        sig_list.append(sig)
                    innerline = file.readline()

                signature_dict[label] = sig_list

            line = file.readline()

    return signature_dict


def get_quirks(row) -> str:
    quirks = []
    quirks_string = ""
    # is getattr working on pandas, i dont think so because every row has column and they fill it with "NaN" or ""
    df = getattr(row, "IP_Flags", "")
    id = getattr(row, "ID")
    tcp_flags = getattr(row, "TCP_Flags")
    ecn = "ecn" if "ECE" in tcp_flags else ""
    urgf = " urgf+" if "URG" in tcp_flags else ""
    urgp = getattr(row, "SYN_URGP", 0)
    push = "pushf+" if "PSH" in tcp_flags else ""

    # print(df)
    if df:
        quirks.append("df")
    # id+
    if df and id > 1:
        quirks.append("id+")
    # id-
    if not df and id == 0:
        quirks.append("id-")

    if ecn:
        quirks.append("ecn")

    # uptr+
    if not urgf and urgp > 0:
        quirks.append("uptr+")

    # urgf+
    if urgf:
        quirks.append("urgf+")

    # pushf+
    if push:
        quirks.append("pushf+")

    quirks_string = ','.join(x for x in quirks)
    # print(f"quirks: {quirks_string}")
    return quirks_string


def create_olayout(options: dict) -> str:
    signature_string = ','.join([translate_to_signature_abbreviations(x, options) for x in options.keys()])
    return signature_string


def decode_tcp_options(options_hex: str) -> OrderedDict:
    ordered_dict = OrderedDict()

    if options_hex.startswith("00"):
        # print(f"Detection: malformed tcp options: {debug_hex}")
        return ordered_dict

    while options_hex:
        option = options_hex[:2]

        length = 0

        tcp_option = tcp_option_types.get(option)
        if tcp_option:
            length = tcp_option.get("length")
            # cut out option byte
            options_hex = options_hex[2:]

            remaining_length = 0
            if not length == 0:
                # cut out length byte
                options_hex = options_hex[2:]
                remaining_length = length - 2

            # there are some malformed tcp options because eol can only happen on end of option string, so return after this
            if length == 0 and option == "00":

                # count followed padding
                padding_count_in_bytes = 0

                while options_hex:
                    padding_count_in_bytes += 1
                    options_hex = options_hex[2:]
                ordered_dict[tcp_option.get("name")] = padding_count_in_bytes

                return ordered_dict

            value = options_hex[:remaining_length * 2]
            ordered_dict[tcp_option.get("name")] = value

            options_hex = options_hex[remaining_length * 2:]
        else:
            # when tcp option value not supported, return empty dict
            return OrderedDict()

    return ordered_dict


def translate_to_signature_abbreviations(name: str, options: dict) -> str:
    """ olayout
        comma-delimited

           eol+n  - explicit end of options, followed by n bytes of padding
           nop    - no-op option
           mss    - maximum segment size
           ws     - window scaling
           sok    - selective ACK permitted
           sack   - selective ACK (should not be seen)
           ts     - timestamp
           ?n     - unknown option ID n
    """

    olayout_abbrev = {"End of Option List": "eol",
                      "No-Operation": "nop",
                      "Maximum Segment Size": "mss",
                      "Window Scale": "ws",
                      "SACK Permitted": "sok",
                      "SACK": "sack",
                      "Timestamps": "ts"}

    abbrev = olayout_abbrev.get(name)
    if abbrev == "eol":
        abbrev = abbrev + "+{}".format(options.get(name))

    return abbrev


def hex_to_decimal(hex: str) -> int:
    decimal = int(hex, 16)
    return decimal


def load_logs_from_csv(path: str, columns: List[str] = None) -> pd.DataFrame:
    if columns is None:
        columns = []

    df = pd.read_csv(path, engine="pyarrow", usecols=columns)

    # some ID fields have empty strings, i don't know why
    # its because there are only 41 fields without id, pandas seems to replace empty object type with ""
    # Fill empty string with NaN
    df['ID'] = pd.to_numeric(df['ID'], errors='coerce')

    # There are 2 LEN Parameters in UDP Packets
    # Convert List in String (through csv) to list
    df['LEN'] = df['LEN'].str.strip(r"[]").str.replace("'", '').str.replace(" ", "").str.split(',')
    # Just keep first element of list
    df['LEN'] = df['LEN'].apply(lambda x: int(x[0]))

    # There are several TTLs values when ICMP over UDP oder ICMP over GRE/EGP... (TTL: 244)
    # Convert List in String (through csv) to real list in Pandas
    df['TTL'] = df['TTL'].astype(str).str.strip(r"[]").str.replace("'", '').str.replace(" ", "").str.split(',')

    # Just keep first element of list
    df['TTL'] = df['TTL'].apply(lambda x: int(x[0]))

    # Fill NAs with -1
    df['SYN_URGP'] = df['SYN_URGP'].fillna(-1)
    df['ID'] = df['ID'].fillna(-1)

    df = df.astype(
        {"DPT": "Int64", "SPT": "Int64", "SYN_URGP": "Int64", "TTL": "Int64", "WINDOW": "Int64", "ID": "Int64",
         "LEN": "Int64"})

    return df


def remove_duplicates_from_df(df: pd.DataFrame) -> pd.DataFrame:
    shrinked_df = df.drop_duplicates(subset=["TCP_Options", "SRC", "DPT"])
    return shrinked_df


def export_df_signature_lines():
    pass


def export_unique_ips_with_label():
    pass


if __name__ == '__main__':
    tcp_option_hex = '020405B4'
    print(decode_tcp_options(tcp_option_hex))
