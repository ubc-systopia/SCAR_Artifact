#include "dsp.h"
#include "log.h"
#include <fftw3.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
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

double *power_spectral_density_welch(double *signal,
                                     uint32_t N,
                                     uint32_t fs,
                                     uint32_t nperseg) {
	int noverlap = nperseg / 2;
	int step = nperseg - noverlap;
	int num_segments = (N - noverlap) / step;

	double *in = fftw_malloc(sizeof(double) * nperseg);
	fftw_complex *out = fftw_malloc(sizeof(fftw_complex) * (nperseg / 2 + 1));
	fftw_plan plan;

	plan = fftw_plan_dft_r2c_1d(nperseg, in, out, FFTW_ESTIMATE);

	double *psd = malloc(sizeof(double) * (int)(nperseg / 2 + 1));

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

double *probes_to_signal(uint64_t *tsc,
                         uint32_t N,
                         uint32_t sample_interval,
                         uint32_t *num_signal) {
	int zero_padding = 240000;
	*num_signal = ceil((double)(tsc[N - 1] - tsc[0]) / sample_interval) +
	              zero_padding * 2;
	double *signal = malloc(sizeof(double) * *num_signal);
	memset(signal, 0, sizeof(double) * *num_signal);
	for (int i = 0; i < N; ++i) {
		int slot =
		    round((double)(tsc[i] - tsc[0]) / sample_interval) + zero_padding;
		signal[slot] = 1;
	}
	return signal;
}

int *find_peaks(double *x,
                uint32_t length,
                uint32_t *peaks_cnt,
                double prominence_thres) {
	int i = 0;
	double global_peak = 0, peak_height = 0, local_peak_ratio = 0.05;
	int *peaks = NULL;
	for (int i = 0; i < length; ++i) {
		global_peak = __max(global_peak, x[i]);
	}
	peak_height = global_peak * local_peak_ratio;

	peaks = malloc(sizeof(*peaks) * length);

	*peaks_cnt = 0;
	i = 1;
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

static int compare_u64(const void *a, const void *b) {
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static uint64_t median_u64(uint64_t *values, uint32_t count) {
	qsort(values, count, sizeof(*values), compare_u64);
	if (count & 1) {
		return values[count / 2];
	}
	uint64_t a = values[count / 2 - 1];
	uint64_t b = values[count / 2];
	return a + (b - a) / 2;
}

static uint64_t estimate_burst_period_c(const uint64_t *hits,
                                        uint32_t count,
                                        uint64_t gap_split) {
	uint64_t *starts = malloc(sizeof(*starts) * count);
	uint64_t *steps = malloc(sizeof(*steps) * count);
	uint64_t *core = malloc(sizeof(*core) * count);
	if (!starts || !steps || !core) {
		free(starts);
		free(steps);
		free(core);
		return 0;
	}

	uint32_t nstarts = 1;
	starts[0] = hits[0];
	for (uint32_t i = 1; i < count; ++i) {
		if (hits[i] - hits[i - 1] > gap_split) {
			starts[nstarts++] = hits[i];
		}
	}
	if (nstarts < 4) {
		free(starts);
		free(steps);
		free(core);
		return 0;
	}

	for (uint32_t i = 1; i < nstarts; ++i) {
		steps[i - 1] = starts[i] - starts[i - 1];
	}
	uint64_t period = median_u64(steps, nstarts - 1);
	uint32_t ncore = 0;
	/* Trace periods are many orders below these overflow guards. Keeping the
	 * comparisons integral makes this identical to a small embedded/CSI port. */
	if (period <= UINT64_MAX / 180) {
		for (uint32_t i = 1; i < nstarts; ++i) {
			uint64_t step = starts[i] - starts[i - 1];
			if (step * 100 > period * 55 && step * 100 < period * 180) {
				core[ncore++] = step;
			}
		}
	}
	if (ncore) {
		period = median_u64(core, ncore);
	}

	free(starts);
	free(steps);
	free(core);
	return period;
}

int analyze_burst_pattern(const uint64_t *timestamps,
                          uint32_t count,
                          uint64_t gap_split,
                          uint32_t max_periods,
                          uint64_t period_hint,
                          burst_pattern_stats_t *stats) {
	if (!timestamps || !stats || !gap_split || count < 8) {
		return 0;
	}
	memset(stats, 0, sizeof(*stats));

	uint64_t *hits = malloc(sizeof(*hits) * count);
	if (!hits) {
		return 0;
	}
	uint32_t nhits = 0;
	for (uint32_t i = 0; i < count; ++i) {
		if (timestamps[i]) {
			hits[nhits++] = timestamps[i];
		}
	}
	if (nhits < 8) {
		free(hits);
		return 0;
	}
	qsort(hits, nhits, sizeof(*hits), compare_u64);
	uint32_t unique = 1;
	for (uint32_t i = 1; i < nhits; ++i) {
		if (hits[i] != hits[unique - 1]) {
			hits[unique++] = hits[i];
		}
	}
	nhits = unique;

	uint64_t period = period_hint ?
	                      period_hint :
	                      estimate_burst_period_c(hits, nhits, gap_split);
	if (!period) {
		free(hits);
		return 0;
	}
	stats->period = period;

	uint32_t roi_left = 0, roi_right = nhits - 1;
	if (max_periods) {
		if (period > UINT64_MAX / max_periods) {
			free(hits);
			return 0;
		}
		uint64_t width = period * max_periods;
		uint32_t left = 0, best_left = 0, best_right = 0;
		for (uint32_t right = 0; right < nhits; ++right) {
			while (hits[right] - hits[left] > width) {
				++left;
			}
			if (right - left > best_right - best_left) {
				best_left = left;
				best_right = right;
			}
		}
		roi_left = best_left;
		roi_right = best_right;
		stats->window_start = hits[best_left];
		stats->window_end = hits[best_left] + width;
	} else {
		stats->window_start = hits[0];
		stats->window_end = hits[nhits - 1] + 1;
	}
	stats->event_count = roi_right - roi_left + 1;

	uint64_t skip_threshold = period + period / 2;
	for (uint32_t i = roi_left + 1; i <= roi_right; ++i) {
		uint64_t gap = hits[i] - hits[i - 1];
		if (gap <= gap_split) {
			++stats->intra_intervals;
		} else if (gap < skip_threshold) {
			++stats->next_intervals;
		} else {
			++stats->skipped_intervals;
		}
	}

	uint64_t *centers = malloc(sizeof(*centers) * stats->event_count);
	if (!centers) {
		free(hits);
		return 0;
	}
	uint32_t ncenters = 0;
	uint32_t begin = roi_left;
	for (uint32_t i = roi_left + 1; i <= roi_right + 1; ++i) {
		bool end = i > roi_right || hits[i] - hits[i - 1] > gap_split;
		if (!end) {
			continue;
		}
		uint64_t offset_sum = 0;
		for (uint32_t j = begin + 1; j < i; ++j) {
			offset_sum += hits[j] - hits[begin];
		}
		centers[ncenters++] = hits[begin] + offset_sum / (i - begin);
		begin = i;
	}
	stats->burst_count = ncenters;

	for (uint32_t i = 1; i < ncenters; ++i) {
		uint64_t gap = centers[i] - centers[i - 1];
		uint64_t multiple = gap / period;
		uint64_t remainder = gap % period;
		if (remainder >= (period + 1) / 2) {
			++multiple;
		}
		if (multiple < 1) {
			multiple = 1;
		}
		uint32_t bin = multiple >= BURST_GAP_HIST_BINS ?
		                   BURST_GAP_HIST_BINS - 1 :
		                   (uint32_t)multiple - 1;
		++stats->gap_hist[bin];
		stats->inferred_missing += multiple - 1;
	}
	stats->inferred_periods =
	    (ncenters ? ncenters - 1 : 0) + stats->inferred_missing;
	stats->period_count_within_max = !max_periods ||
	                                 stats->inferred_periods <= max_periods;
	if (stats->inferred_periods) {
		stats->missing_rate =
		    (double)stats->inferred_missing / (double)stats->inferred_periods;
	}

	free(centers);
	free(hits);
	return 1;
}

int check_cache_set_psd(uint64_t *probes,
                        uint32_t n_probes,
                        uint32_t fs,
                        uint32_t target_base_freq) {
	if (n_probes == 0) {
		return 0;
	}
	uint32_t num_signal;

	int nperseg = 2048;
	double *signal =
	    probes_to_signal(probes, n_probes, PS_sample_interval, &num_signal);
	double *psd = power_spectral_density_welch(signal, num_signal, fs, nperseg);
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
		int *peak_indice = find_peaks(psd, length, &peaks_cnt, 0.5);
		if (peaks_cnt < peak_check_num) {
			ret = 0;
		}
		memset(peak_occurrence, 0, sizeof(peak_occurrence));
		log_debug(
		    "global peak %.10lf, peaks count: %d", global_peak, peaks_cnt);
		for (int i = 0; i < peaks_cnt && ret; ++i) {
			if (psd[peak_indice[i]] < global_peak * 0.2) {
				continue;
			}
			double freq = (double)peak_indice[i] * fs / nperseg;
			int round_i = round(freq / target_base_freq);
			double round_freq = round_i * target_base_freq;
			log_debug("peak %.10lf, round %d, psd: %.10lf",
			          freq,
			          round_i,
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

int check_cpython_pow_psd(uint64_t *probes,
                          uint32_t n_probes,
                          double fs,
                          double side_freq,
                          uint32_t target_base_freq) {
	if (n_probes == 0) {
		return 0;
	}
	uint32_t num_signal;

	int nperseg = 2048;
	double *signal =
	    probes_to_signal(probes, n_probes, PS_sample_interval, &num_signal);
	double *psd = power_spectral_density_welch(signal, num_signal, fs, nperseg);
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
		int *peak_indice = find_peaks(psd, length, &peaks_cnt, 0.5);
		if (peaks_cnt < peak_check_num) {
			ret = 0;
		}
		memset(peak_occurrence, 0, sizeof(peak_occurrence));
		log_debug(
		    "global peak %.10lf, peaks count: %d", global_peak, peaks_cnt);
		for (int i = 0; i < peaks_cnt && ret; ++i) {
			double freq = (double)peak_indice[i] * fs / nperseg;
			int round_i = round(freq / target_base_freq);
			double round_freq = round_i * target_base_freq;
			log_debug("peak %.10lf, round %d, psd: %.10lf",
			          freq,
			          round_i,
			          psd[peak_indice[i]]);
			if (round_i && round_i <= peak_check_num) {
				double diff = fabs(freq - round_freq);
				if (diff < 1000) {
					ret = psd[peak_indice[i]] > global_peak * 0.7;
				} else {
					ret = psd[peak_indice[i]] < global_peak * 0.2;
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

int check_cpython_pow_gap(uint64_t *probes,
                          uint32_t n_probes,
                          uint64_t unit_cycles,
                          uint32_t hits_exp,
                          uint32_t long_mult,
                          uint32_t short_long_ratio) {
	if (n_probes < 2) {
		return 0;
	}

	double tol = 0.1;
	const uint64_t lo1 = unit_cycles * (1 - tol),
	               hi1 = unit_cycles * (1 + tol);
	const uint64_t lo2 = long_mult * unit_cycles * (1 - tol),
	               hi2 = long_mult * unit_cycles * (1 + tol);

	uint64_t short_cnt = 0, long_cnt = 0, other_cnt = 0;
	for (uint32_t i = 1; i < n_probes; ++i) {
		if (probes[i] == 0) {
			break;
		}
		uint64_t gap = probes[i] - probes[i - 1];
		if (gap >= lo1 && gap <= hi1) {
			++short_cnt;
		} else if (gap >= lo2 && gap <= hi2) {
			++long_cnt;
		} else {
			++other_cnt;
		}
	}

	uint64_t total = short_cnt + long_cnt + other_cnt;
	log_info("gap check: short=%lu long=%lu other=%lu total=%lu",
	         short_cnt, long_cnt, other_cnt, total);

	if (total < hits_exp * (1 - tol) || total > hits_exp * (1 + tol)) {
		return 0;
	}
	if (long_cnt == 0) {
		return 0;
	}
	if ((short_cnt + long_cnt) * 100 < total * 95) {
		return 0;
	}

	return (uint32_t)round((double)short_cnt / long_cnt) == short_long_ratio;
}

int check_cpython_pow_gap_alt(uint64_t *probes,
                              uint32_t n_probes,
                              uint64_t unit_a,
                              uint64_t unit_b) {
	if (n_probes < 2) {
		return 0;
	}

	const uint64_t tol_a = unit_a / 10;
	const uint64_t lo_a = unit_a - tol_a, hi_a = unit_a + tol_a;
	const uint64_t tol_b = unit_b / 10;
	const uint64_t lo_b = unit_b - tol_b, hi_b = unit_b + tol_b;

	uint64_t cnt_a = 0, cnt_b = 0, other_cnt = 0;
	uint32_t n_gaps = 0;
	uint32_t alt_violations = 0;
	int last_type = 0; /* 0=unset, 1=a, 2=b */

	for (uint32_t i = 1; i < n_probes; ++i) {
		if (probes[i] == 0) {
			break;
		}
		uint64_t gap = probes[i] - probes[i - 1];
		++n_gaps;

		int cur_type;
		if (gap >= lo_a && gap <= hi_a) {
			++cnt_a;
			cur_type = 1;
		} else if (gap >= lo_b && gap <= hi_b) {
			++cnt_b;
			cur_type = 2;
		} else {
			++other_cnt;
			cur_type = 0;
		}

		if (last_type != 0 && cur_type != 0 && cur_type == last_type) {
			++alt_violations;
		}
		if (cur_type != 0) {
			last_type = cur_type;
		}
	}

	log_info("gap alt check: a=%lu b=%lu other=%lu total=%u alt_violations=%u",
	         cnt_a, cnt_b, other_cnt, n_gaps, alt_violations);

	double hits_ratio = 0.1, hits_exp = 8192;
	if (n_gaps < hits_exp * (1 - hits_ratio) ||
	    n_gaps > hits_exp * (1 + hits_ratio)) {
		return 0;
	}
	if (cnt_a == 0 || cnt_b == 0) {
		return 0;
	}
	if ((cnt_a + cnt_b) * 100 < (uint64_t)n_gaps * 95) {
		return 0;
	}
	/* allow up to 5% alternation violations */
	if (alt_violations * 20 > n_gaps) {
		return 0;
	}

	return 1;
}

#undef __max
#undef __min
