#include "dsp.h"
#include "log.h"
#include <fftw3.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define __max(a, b)             \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a > _b ? _a : _b;      \
    })

#define __min(a, b)             \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a < _b ? _a : _b;      \
    })

static int fequal(double a, double b) {
    return fabs(a - b) < 1e-9;
}

double* power_spectral_density_welch(double* signal,
                                     uint32_t N,
                                     uint32_t fs,
                                     uint32_t nperseg) {
    int noverlap = nperseg / 2;
    int step = nperseg - noverlap;
    int num_segments = (N - noverlap) / step;

    double* in = fftw_malloc(sizeof(double) * nperseg);
    fftw_complex* out = fftw_malloc(sizeof(fftw_complex) * (nperseg / 2 + 1));
    fftw_plan plan;

    plan = fftw_plan_dft_r2c_1d(nperseg, in, out, FFTW_ESTIMATE);

    double* psd = malloc(sizeof(double) * (int)(nperseg / 2 + 1));

    for (int i = 0; i < nperseg / 2 + 1; i++) {
        psd[i] = 0;
    }

    double window[nperseg];

    // hanning_window
    for (int i = 0; i < nperseg; i++) {
        window[i] = 0.5 * (1 - cos(2 * M_PI * i / (nperseg - 1)));
    }

    for (int segment = 0; segment < num_segments; segment++) {
        int start = segment * step;

        double segment_mean = 0.0;
        for (int i = 0; i < nperseg; i++) {
            segment_mean += signal[start + i];
        }
        segment_mean /= nperseg;

        for (int i = 0; i < nperseg; i++) {
            if (start + i < N) {
                in[i] = (signal[start + i] - segment_mean) * window[i];
            } else {
                in[i] = 0;
            }
        }

        fftw_execute(plan);

        for (int i = 0; i < nperseg / 2 + 1; i++) {
            double real = out[i][0];
            double imag = out[i][1];
            double power = (real * real + imag * imag) / (fs * nperseg);
            psd[i] += power;
        }
    }
    double window_sum = 0.0;
    for (int i = 0; i < nperseg; i++) {
        window_sum += window[i] * window[i];
    }
    window_sum /= nperseg;

    for (int i = 0; i < nperseg / 2 + 1; i++) {
        psd[i] /= window_sum;
    }

    fftw_destroy_plan(plan);
    fftw_free(in);
    fftw_free(out);
    return psd;
}

double* probes_to_signal(uint64_t* tsc,
                         uint32_t N,
                         uint32_t sample_interval,
                         uint32_t* num_signal) {
    int zero_padding = 240000;
    *num_signal = ceil((double)(tsc[N - 1] - tsc[0]) / sample_interval) +
                  zero_padding * 2;
    double* signal = malloc(sizeof(double) * *num_signal);
    memset(signal, 0, sizeof(double) * *num_signal);
    for (int i = 0; i < N; ++i) {
        int slot =
            round((double)(tsc[i] - tsc[0]) / sample_interval) + zero_padding;
        signal[slot] = 1;
    }
    return signal;
}

int* find_peaks(double* x,
                uint32_t length,
                uint32_t* peaks_cnt,
                double prominence_thres) {
    int i = 0, peaks_cnt_limit = 64;
    double global_peak = 0, peak_height = 0, local_peak_ratio = 0.05;
    int* peaks = NULL;
    for (int i = 0; i < length; ++i) {
        global_peak = __max(global_peak, x[i]);
    }
    peak_height = global_peak * local_peak_ratio;

    peaks = malloc(sizeof(double) * peaks_cnt_limit);

    *peaks_cnt = 0;
    i = 0;
    while (i < length - 1) {
        if (x[i - 1] < x[i] && x[i] > x[i + 1]) {
            int left_valley = i - 1;
            while (left_valley > 0 && x[left_valley] >= x[left_valley - 1]) {
                left_valley--;
            }

            int right_valley = i + 1;
            while (right_valley < length - 1 &&
                   x[right_valley] >= x[right_valley + 1]) {
                right_valley++;
            }
            double prominence_ratio =
                fmin(x[left_valley], x[right_valley]) / x[i];
            if (prominence_ratio < prominence_thres) {
                peaks[(*peaks_cnt)++] = i;
            }
        }
        ++i;
    }
    return peaks;
}

const uint64_t cpu_freq = 2800000000;
const uint32_t PS_sample_interval = 10000;
const uint32_t PS_fs = cpu_freq / PS_sample_interval;

int check_cache_set_psd(uint64_t* probes,
                        uint32_t n_probes,
                        uint32_t fs,
                        uint32_t target_base_freq) {
    if (n_probes == 0) {
        return 0;
    }
    uint32_t num_signal;

    int nperseg = 2048;
    double* signal =
        probes_to_signal(probes, n_probes, PS_sample_interval, &num_signal);
    double* psd = power_spectral_density_welch(signal, num_signal, fs, nperseg);
    uint32_t length = nperseg / 2 + 1;

    int peak_freq_range = 1000;
    const int peak_check_num = 4;
    int peak_occurrence[peak_check_num + 1];
    double global_peak = 0;
    int ret = 0;
    for (int i = 0; i < length; ++i) {
        global_peak = __max(global_peak, psd[i]);
    }
    if (global_peak > 1e-6) {
        ret = 1;
        uint32_t peaks_cnt;
        int* peak_indice = find_peaks(psd, length, &peaks_cnt, 0.5);
        if (peaks_cnt < peak_check_num) {
            ret = 0;
        }
        memset(peak_occurrence, 0, sizeof(peak_occurrence));
        log_debug("global peak %.10lf, peaks count: %d", global_peak,
                  peaks_cnt);
        for (int i = 0; i < peaks_cnt && ret; ++i) {
            double freq = (double)peak_indice[i] * fs / nperseg;
            int round_i = round(freq / target_base_freq);
            double round_freq = round_i * target_base_freq;
            log_trace("peak %.10lf, round %d, psd: %.10lf", freq, round_i,
                      psd[peak_indice[i]]);
            if (round_i && round_i <= peak_check_num) {
                double diff = fabs(freq - round_freq);
                if (diff > 1000) {
                    ret = psd[peak_indice[i]] < global_peak * 0.2;
                } else {
                    ret = psd[peak_indice[i]] > global_peak * 0.7;
                }
                peak_occurrence[round_i] = 1;
            }
        }
        for (int i = 1; i <= peak_check_num; ++i) {
            if (peak_occurrence[i] != 1) {
                log_debug("no occurrence on %d", i);
                ret = 0;
                break;
            }
        }
        free(peak_indice);
    }
    free(signal);
    free(psd);

    return ret;
}

#undef __max
#undef __min
