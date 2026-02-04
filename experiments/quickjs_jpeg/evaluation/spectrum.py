import math
import re  # Import the re module for regular expressions

import numpy as np
import pandas as pd
from bokeh.io import output_file, show
from bokeh.layouts import column, row
from bokeh.palettes import Colorblind
from bokeh.plotting import figure
from scipy.signal import butter, filtfilt, welch, find_peaks

from utils import *

def probes_to_signal(probes, sample_interval, duration=None, zero_padding=1000):
    probes = np.array(probes)
    probes = probes[probes != 0]
    if len(probes) == 0:
        return []

    if not duration:
        duration = (probes[0], probes[-1])
    else:
        assert(duration[0] <= probes[0] and probes[-1] <= duration[1])
    num_signal = (
        math.ceil((duration[1] - duration[0]) / sample_interval) + zero_padding * 2
    )
    signal = np.array([0 for _ in range(num_signal + 1)])
    for p in probes:
        slot = round((p - duration[0]) / sample_interval) + zero_padding
        # print(p, duration[0], slot)
        signal[slot] = 1
    return signal

def get_plot_fft(signal, fs):
    frequencies = np.fft.fftfreq(len(signal), 1 / fs)
    fft_values = np.fft.fft(signal)

    p_fft = figure(
        title="Frequency Spectrum",
        x_axis_label="Frequency (Hz)",
        y_axis_label="Amplitude",
        width=600,
        height=300,
    )
    p_fft.line(
        frequencies[: len(frequencies) // 2], np.abs(fft_values[: len(fft_values) // 2])
    )
    return p_fft


def bandpass_filter(data, lowcut, highcut, fs, order=5):
    nyquist = 0.5 * fs
    low = lowcut / nyquist
    high = highcut / nyquist
    b, a = butter(order, [low, high], btype="band")
    y = filtfilt(b, a, data)
    return y


def threshold_to_binary(filtered_signal, threshold):
    binary_signal = np.where(filtered_signal > threshold, 1, 0)
    return binary_signal


def lowpass_filter(data, cutoff, fs, order=5):
    nyquist = 0.5 * fs
    low = cutoff / nyquist
    b, a = butter(order, low, btype="low")
    y = filtfilt(b, a, data)
    return y


def get_plot_signal(signal):
    emit_data = load_cloud_emit_data()

    p_signal = figure(
        title="Emitted/Received/Filtered Signal",
        x_axis_label="Time [2000 tsc]",
        width=1200,
        height=600,
    )

    low_freq_signal = lowpass_filter(signal, 5, fs)
    filtered_signal1 = low_freq_signal
    base_freq = 100
    for freq in range(base_freq, fs // 2, base_freq):
        filtered_signal1 += bandpass_filter(signal, freq - 5, freq + 5, fs)

    binary_signal1 = threshold_to_binary(filtered_signal1, 0.4)

    emit_data_slot = emit_data // fs + zero_padding
    received_data_slot = list(filter(lambda i: signal[i], range(len(signal))))
    filtered_data_slot = list(
        filter(lambda i: binary_signal1[i], range(len(binary_signal1)))
    )
    palette = Colorblind[3]
    p_signal.scatter(
        marker="dot",
        x=emit_data_slot,
        y=0,
        size=30,
        color=palette[0],
        legend_label="Emitted",
    )
    p_signal.scatter(
        marker="dot",
        x=received_data_slot,
        y=1,
        size=30,
        color=palette[1],
        legend_label="Received",
    )
    p_signal.scatter(
        marker="dot",
        x=filtered_data_slot,
        y=2,
        size=30,
        color=palette[2],
        legend_label="filtered",
    )
    p_signal.legend.click_policy = "hide"
    p_signal.add_layout(p_signal.legend[0], "right")
    p_signal.title.text_font_size = "16pt"
    p_signal.legend.label_text_font_size = "12pt"
    p_signal.legend.glyph_height = 40
    p_signal.legend.glyph_width = 40
    p_signal.yaxis.ticker = [0, 1, 2]
    p_signal.yaxis.major_label_overrides = {0: "Emitted", 1: "Received", 2: "Filtered"}
    p_signal.xaxis.axis_label_text_font_size = "16pt"
    p_signal.xaxis.major_label_text_font_size = "16pt"
    p_signal.yaxis.axis_label_text_font_size = "16pt"
    p_signal.yaxis.major_label_text_font_size = "16pt"
    return p_signal


def get_plot_wave(signal):
    p_wave = figure(
        title="Filtered Wave",
        x_axis_label="Time [2000 tsc]",
        width=600,
        height=300,
    )

    low_freq_signal = lowpass_filter(signal, 5, fs)
    filtered_signal1 = low_freq_signal
    base_freq = 100
    for freq in range(base_freq, fs // 2, base_freq):
        filtered_signal1 += bandpass_filter(signal, freq - 5, freq + 5, fs)

    p_wave.line(x=list(range(len(filtered_signal1))), y=filtered_signal1)
    return p_wave


def find_psd_peaks(signal, fs):
    if len(signal) == 0:
        return []
    frequencies_psd, psd_values = welch(signal, fs)
    n_freq = len(frequencies_psd)
    psd_x = frequencies_psd[: n_freq // 2] / 1000
    psd_y = psd_values[: n_freq // 2] * (10**7)

    peaks, props = find_peaks(psd_y, prominence=0.05*np.max(psd_y))
    if len(peaks) == 0:
        return []
    return psd_x[peaks]


def find_trace_psd_peaks(trace, sample_interval, fs=2400000, att="PS"):
    pos = trace.apply(lambda x: lat_to_hit(x[0][1], att), axis=1)
    probe_hits = list(trace[pos].apply(lambda x: x[0][0], axis=1))
    signal = probes_to_signal(probe_hits, sample_interval)
    return find_psd_peaks(signal, fs)
