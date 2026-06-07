use tensorguard_core::PoolSnapshot;

/// Direction of the pending swap
#[derive(Debug, Clone, Copy)]
pub enum SwapDirection {
    /// Token A → Token B  (reserve_x increases)
    ZeroForOne,
    /// Token B → Token A  (reserve_y increases)
    OneForZero,
}

/// A pending swap detected in the mempool
#[derive(Debug, Clone)]
pub struct PendingSwap {
    pub amount_in:  u128,
    pub direction:  SwapDirection,
    pub slot:       u64,
}

/// Projects the EXPECTED pool state after a pending swap executes.
///
/// For a constant-product AMM (x * y = k):
///   ZeroForOne: new_x = x + amount_in,  new_y = k / new_x
///   OneForZero: new_y = y + amount_in,  new_x = k / new_y
///
/// This lets the daemon evaluate TensorGuard on the PROJECTED state —
/// BEFORE the transaction is included in a block.
pub fn project_swap(current: &PoolSnapshot, swap: &PendingSwap) -> PoolSnapshot {
    let k = current.reserve_x * current.reserve_y;

    let (new_x, new_y) = match swap.direction {
        SwapDirection::ZeroForOne => {
            let nx = current.reserve_x.saturating_add(swap.amount_in);
            let ny = if nx > 0 { k / nx } else { current.reserve_y };
            (nx, ny)
        }
        SwapDirection::OneForZero => {
            let ny = current.reserve_y.saturating_add(swap.amount_in);
            let nx = if ny > 0 { k / ny } else { current.reserve_x };
            (nx, ny)
        }
    };

    PoolSnapshot {
        reserve_x: new_x,
        reserve_y: new_y,
        block:     swap.slot,
        timestamp: swap.slot * 400, // ~400ms per slot
    }
}

/// Estimate the price impact of a pending swap as a ratio.
/// impact = |new_price - old_price| / old_price
pub fn price_impact(current: &PoolSnapshot, swap: &PendingSwap) -> f64 {
    let projected = project_swap(current, swap);

    let old_price = current.reserve_x as f64 / current.reserve_y.max(1) as f64;
    let new_price = projected.reserve_x as f64 / projected.reserve_y.max(1) as f64;

    (new_price - old_price).abs() / old_price.max(f64::EPSILON)
}
