use super::state::LiquidityTensor;

/// Lyapunov V(T):
/// Tracks kinetic energy of price movement relative to historical baseline.
/// V = (current_velocity / baseline_velocity)²
/// A spike in V means price is moving WAY faster than normal → unstable.

pub struct LyapunovMetric {
    velocity_history: Vec<f64>,
    window: usize,
}

impl LyapunovMetric {
    pub fn new(window: usize) -> Self {
        Self {
            velocity_history: Vec::with_capacity(window),
            window,
        }
    }

    fn price_velocity(tensor: &LiquidityTensor) -> f64 {
        let [vx, vy] = tensor.velocity;
        // Rate of price change: d(x/y)/dt approximation
        let speed = (vx.powi(2) + vy.powi(2)).sqrt();
        let scale = (tensor.x.powi(2) + tensor.y.powi(2)).sqrt().max(1.0);
        speed / scale
    }

    fn baseline(&self) -> f64 {
        if self.velocity_history.is_empty() {
            return 1.0;
        }
        let sum: f64 = self.velocity_history.iter().sum();
        (sum / self.velocity_history.len() as f64).max(1e-10)
    }

    /// Returns normalized energy ratio: current / baseline
    /// > 1.0 means faster than normal, > threshold means danger
    pub fn update(&mut self, tensor: &LiquidityTensor) -> f64 {
        let v = Self::price_velocity(tensor);
        let base = self.baseline();

        if self.velocity_history.len() >= self.window {
            self.velocity_history.remove(0);
        }
        self.velocity_history.push(v);

        v / base
    }
}
