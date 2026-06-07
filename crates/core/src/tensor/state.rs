/// Raw snapshot from AMM pool at a given block
#[derive(Debug, Clone)]
pub struct PoolSnapshot {
    pub reserve_x: u128,
    pub reserve_y: u128,
    pub block: u64,
    pub timestamp: u64,
}

/// The 5-dimensional state that defines our manifold
///   T(x, y, t, v, ρ)
#[derive(Debug, Clone)]
pub struct LiquidityTensor {
    /// Reserve token A (normalized)
    pub x: f64,
    /// Reserve token B (normalized)
    pub y: f64,
    /// Block timestamp
    pub t: f64,
    /// Velocity vector [dx/dt, dy/dt]
    pub velocity: [f64; 2],
    /// Liquidity density: sqrt(x*y) / price_range
    pub density: f64,
    /// Invariant k = x * y at equilibrium
    pub k: f64,
}

impl LiquidityTensor {
    /// Build tensor from two consecutive snapshots
    pub fn from_snapshots(prev: &PoolSnapshot, curr: &PoolSnapshot) -> Self {
        let x = curr.reserve_x as f64;
        let y = curr.reserve_y as f64;
        let dt = (curr.timestamp - prev.timestamp).max(1) as f64;

        let dx = (curr.reserve_x as f64) - (prev.reserve_x as f64);
        let dy = (curr.reserve_y as f64) - (prev.reserve_y as f64);

        let k = x * y;
        let price = x / y;
        let density = k.sqrt() / price.max(f64::EPSILON);

        LiquidityTensor {
            x,
            y,
            t: curr.timestamp as f64,
            velocity: [dx / dt, dy / dt],
            density,
            k,
        }
    }

    /// Expected price on the invariant curve: y = k / x
    pub fn expected_y(&self) -> f64 {
        self.k / self.x.max(f64::EPSILON)
    }

    /// Observed price: x / y
    pub fn price(&self) -> f64 {
        self.x / self.y.max(f64::EPSILON)
    }

    /// Deviation from invariant (should be ~0 for honest swaps)
    pub fn invariant_deviation(&self) -> f64 {
        let observed_k = self.x * self.y;
        (observed_k - self.k).abs() / self.k.max(f64::EPSILON)
    }
}
