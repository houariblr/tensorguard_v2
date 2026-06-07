use super::state::LiquidityTensor;

/// Ricci curvature deviation R(T):
/// On the AMM curve y = k/x, the expected curvature at x is:
///   κ = 2k / (x² + k²/x²)^(3/2) * x³
///
/// We measure how much the OBSERVED price trajectory deviates
/// from this expected curve geometry.
/// Normal swap: stays ON the curve → R ≈ 0
/// Attack: violent jump that tears off the curve → R >> 1

pub struct RicciMetric {
    history: Vec<(f64, f64)>, // (price, k) per block
    window: usize,
}

impl RicciMetric {
    pub fn new(window: usize) -> Self {
        Self {
            history: Vec::with_capacity(window),
            window,
        }
    }

    /// Expected |Δprice| for a given |Δreserve_x| on the AMM curve
    /// From y = k/x: Δy ≈ -(k/x²) * Δx
    /// So expected price change: |Δprice| / price ≈ |Δx| / x
    fn expected_relative_move(dx_ratio: f64) -> f64 {
        // On curve y=k/x: price = x/y = x²/k
        // d(price)/dx = 2x/k, so Δprice/price = 2 * Δx/x (for small Δx)
        2.0 * dx_ratio
    }

    /// Returns ratio: observed_move / expected_move
    /// > 1.0 means the move is larger than the curve geometry allows naturally
    pub fn update(&mut self, tensor: &LiquidityTensor) -> f64 {
        let price = tensor.price();

        if self.history.len() >= self.window {
            self.history.remove(0);
        }

        let result = if let Some(&(prev_price, prev_x)) = self.history.last() {
            let observed_move = (price - prev_price).abs() / prev_price.max(1e-10);
            let dx_ratio = (tensor.x - prev_x).abs() / prev_x.max(1e-10);
            let expected = Self::expected_relative_move(dx_ratio).max(1e-10);
            observed_move / expected
        } else {
            0.0
        };

        self.history.push((price, tensor.x));
        result
    }
}
