use super::state::LiquidityTensor;

/// Kolmogorov K(T):
/// Measures entropy of the price return sequence.
/// Normal trading: low entropy (mean-reverting, bounded variance).
/// Attack: HIGH entropy (abrupt jump unlike any prior pattern).
///
/// We use Shannon entropy on discretized price returns as a proxy.

pub struct KolmogorovMetric {
    returns: Vec<f64>,
    window: usize,
    last_price: Option<f64>,
}

impl KolmogorovMetric {
    pub fn new(window: usize) -> Self {
        Self {
            returns: Vec::with_capacity(window),
            window,
            last_price: None,
        }
    }

    fn shannon_entropy(data: &[f64]) -> f64 {
        if data.len() < 4 {
            return 0.0;
        }
        // Discretize into 16 buckets
        let min = data.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = data.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let range = (max - min).max(1e-10);

        let mut counts = [0usize; 16];
        for &v in data {
            let bucket = ((v - min) / range * 15.0) as usize;
            counts[bucket.min(15)] += 1;
        }

        let n = data.len() as f64;
        counts.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / n;
                -p * p.log2()
            })
            .sum()
    }

    /// Returns how many standard deviations the current return
    /// deviates from the historical distribution.
    pub fn update(&mut self, tensor: &LiquidityTensor) -> f64 {
        let price = tensor.price();

        let ret = match self.last_price {
            Some(prev) if prev > 0.0 => (price / prev).ln(),
            _ => {
                self.last_price = Some(price);
                return 0.0;
            }
        };
        self.last_price = Some(price);

        if self.returns.len() < 8 {
            self.returns.push(ret);
            return 0.0;
        }

        // Compute baseline stats from history
        let n = self.returns.len() as f64;
        let mean = self.returns.iter().sum::<f64>() / n;
        let variance = self.returns.iter()
            .map(|&r| (r - mean).powi(2))
            .sum::<f64>() / n;
        let std = variance.sqrt().max(1e-10);

        // Z-score of current return
        let z = (ret - mean).abs() / std;

        if self.returns.len() >= self.window {
            self.returns.remove(0);
        }
        self.returns.push(ret);

        z // > 3.0 = extreme outlier
    }
}
