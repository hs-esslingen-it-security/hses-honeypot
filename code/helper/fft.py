from scipy.fft import fft, fftfreq
import numpy as np
import pandas as pd
import scipy.fft as sf
import matplotlib.pyplot as plt
import matplotlib.ticker as tck

def calculate_fft(df, volume=True):
    df = df.take([19, -1], axis=1)
    new_dict = {}
    new_array = []
    for item in df.iterrows():
        timestamp_day = str(item[1]).replace("  ", " ").replace("  ", " ").replace("  ", " ").replace("  ", " ").replace("  ", " ").replace("  ", " ").replace("  ", " ").replace("  ", " ").replace("  ", " ").replace("  ", " ").split(" ")[1]
        if timestamp_day not in new_dict.keys():
            new_dict[timestamp_day] = 0
        if volume:
            new_dict[timestamp_day] += 1
        else:
            new_dict[timestamp_day] = 1

    from datetime import date, timedelta

    start_date = date(2023, 10, 20) 
    end_date = date(2024, 1, 31) 

    delta = end_date - start_date   # returns timedelta

    very_new_dict = {}
    for i in range(delta.days + 1):
        day = start_date + timedelta(days=i)
        if str(day) not in new_dict:
            very_new_dict[str(day)] = 0
        else:
            very_new_dict[str(day)] = new_dict[str(day)]

    idx = 0
    for item in sorted(list(very_new_dict.keys())):
        new_array.append([item, int(very_new_dict[item])])
        idx += 1
    
    data = np.array(new_array)

    # Sort by date, extract columns in invidual views, remove DC offset
    data = data[data[:,0].argsort()]
    day = data[:,0]
    spots = data[:,1]

    # Get positive DFT of AQI
    N = day.shape[0]
    X = sf.rfft(spots) / N
    freqs = sf.rfftfreq(n=N, d=1)
    return N, X, freqs, day, spots