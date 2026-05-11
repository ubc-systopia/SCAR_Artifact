#pragma once

#include <stdint.h>

double *power_spectral_density_welch(double *signal,
                                     uint32_t N,
                                     uint32_t fs,
                                     uint32_t nperseg);

double *probes_to_signal(uint64_t *tsc,
                         uint32_t N,
                         uint32_t sample_interval,
                         uint32_t *num_signal);

int check_cache_set_psd(uint64_t *probes,
                        uint32_t n_probes,
                        uint32_t fs,
                        uint32_t target_base_freq);

int check_cpython_pow_psd(uint64_t *probes,
                          uint32_t n_probes,
                          double fs,
                          double side_freq,
                          uint32_t target_base_freq);

int check_cpython_pow_gap(uint64_t *probes,
                          uint32_t n_probes,
                          uint64_t unit_cycles,
                          uint32_t hits_exp,
                          uint32_t long_mult,
                          uint32_t short_long_ratio);

int check_cpython_pow_gap_alt(uint64_t *probes,
                              uint32_t n_probes,
                              uint64_t unit_a,
                              uint64_t unit_b);
int *find_peaks(double *x,
                uint32_t length,
                uint32_t *peaks_cnt,
                double prominence_thres);

extern const uint64_t cpu_freq;
extern const uint32_t PS_sample_interval; // PS interval
extern const uint32_t PS_fs; // cpu_freq / sample_interval
