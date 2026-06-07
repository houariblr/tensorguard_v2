use crate::tensor::{
    lyapunov::LyapunovMetric,
    kolmogorov::KolmogorovMetric,
    ricci::RicciMetric,
    state::LiquidityTensor,
};

#[derive(Debug)]
pub struct AttackSignal {
    pub is_attack: bool,
    pub confidence: f64,
    pub triggers: Vec<&'static str>,
    pub lyapunov: f64,
    pub kolmogorov: f64,
    pub ricci: f64,
}

pub struct Thresholds {
    /// Lyapunov: velocity ratio > threshold → anomaly (e.g. 5x faster than normal)
    pub lyapunov: f64,
    /// Kolmogorov: z-score of price return > threshold (e.g. 3 sigma)
    pub kolmogorov: f64,
    /// Ricci: observed/expected move ratio > threshold
    pub ricci: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            lyapunov: 5.0,    // 5x faster than historical baseline
            kolmogorov: 3.0,  // 3 sigma outlier
            ricci: 3.0,       // 3x larger than curve-expected move
        }
    }
}

pub struct TensorGuard {
    lyapunov: LyapunovMetric,
    kolmogorov: KolmogorovMetric,
    ricci: RicciMetric,
    thresholds: Thresholds,
}

impl TensorGuard {
    pub fn new(window: usize, thresholds: Thresholds) -> Self {
        Self {
            lyapunov: LyapunovMetric::new(window),
            kolmogorov: KolmogorovMetric::new(window),
            ricci: RicciMetric::new(window),
            thresholds,
        }
    }

    pub fn with_defaults(window: usize) -> Self {
        Self::new(window, Thresholds::default())
    }

    pub fn evaluate(&mut self, tensor: &LiquidityTensor) -> AttackSignal {
        let l = self.lyapunov.update(tensor);
        let k = self.kolmogorov.update(tensor);
        let r = self.ricci.update(tensor);

        let mut triggers = Vec::new();
        if l > self.thresholds.lyapunov    { triggers.push("lyapunov"); }
        if k > self.thresholds.kolmogorov  { triggers.push("kolmogorov"); }
        if r > self.thresholds.ricci       { triggers.push("ricci"); }

        let confidence = [
            (l / self.thresholds.lyapunov).min(1.0),
            (k / self.thresholds.kolmogorov).min(1.0),
            (r / self.thresholds.ricci).min(1.0),
        ]
        .iter().sum::<f64>() / 3.0;

        AttackSignal {
            is_attack: triggers.len() >= 2, // majority vote (2 of 3)
            confidence,
            triggers,
            lyapunov: l,
            kolmogorov: k,
            ricci: r,
        }
    }
}
