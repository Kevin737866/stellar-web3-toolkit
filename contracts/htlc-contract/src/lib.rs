#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env, Symbol, Vec};

const DAY_IN_LEDGERS: u32 = 17280; // Approximate number of ledgers per day

#[contracttype]
pub enum DataKey {
    Swap(BytesN<32>),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicSwap {
    pub initiator: Address,
    pub participant: Address,
    pub hash_lock: BytesN<32>,
    pub preimage: Option<Bytes>,
    pub initiator_asset: Address,
    pub participant_asset: Address,
    pub initiator_amount: i128,
    pub participant_amount: i128,
    pub timeout_ledger: u32,
    pub status: SwapStatus,
    pub created_at: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SwapStatus {
    Pending,
    Completed,
    Refunded,
    Expired,
}

#[contracttype]
pub struct SwapEvent {
    pub swap_id: BytesN<32>,
    pub status: SwapStatus,
    pub timestamp: u64,
}

#[contract]
pub struct HtlcContract;

#[contractimpl]
impl HtlcContract {
    /// Initialize a new atomic swap
    /// 
    /// # Arguments
    /// * `participant` - The counterparty address
    /// * `hash_lock` - SHA-256 hash of the secret preimage
    /// * `initiator_asset` - Asset address for initiator's deposit
    /// * `participant_asset` - Asset address for participant's deposit
    /// * `initiator_amount` - Amount initiator will deposit
    /// * `participant_amount` - Amount participant will deposit
    /// * `timeout_hours` - Timeout in hours before refund is possible
    /// 
    /// # Returns
    /// BytesN<32> - Unique swap identifier
    pub fn create_swap(
        env: Env,
        participant: Address,
        hash_lock: BytesN<32>,
        initiator_asset: Address,
        participant_asset: Address,
        initiator_amount: i128,
        participant_amount: i128,
        timeout_hours: u32,
    ) -> BytesN<32> {
        let initiator = env.current_contract_address();
        let current_ledger = env.ledger().sequence();
        let timeout_ledger = current_ledger + (timeout_hours * DAY_IN_LEDGERS / 24);

        // Generate unique swap ID
        let mut swap_data = Vec::new(&env);
        swap_data.push_back(initiator.clone().into());
        swap_data.push_back(participant.clone().into());
        swap_data.push_back(hash_lock.clone());
        swap_data.push_back(current_ledger.into());
        let swap_id = env.crypto().sha256(&swap_data.to_bytes());

        let atomic_swap = AtomicSwap {
            initiator: initiator.clone(),
            participant: participant.clone(),
            hash_lock: hash_lock.clone(),
            preimage: None,
            initiator_asset: initiator_asset.clone(),
            participant_asset: participant_asset.clone(),
            initiator_amount,
            participant_amount,
            timeout_ledger,
            status: SwapStatus::Pending,
            created_at: current_ledger,
        };

        // Store the swap
        env.storage().instance().set(&DataKey::Swap(swap_id), &atomic_swap);

        // Emit creation event
        env.events().publish(
            symbol_short!("swap_created"),
            SwapEvent {
                swap_id,
                status: SwapStatus::Pending,
                timestamp: env.ledger().timestamp(),
            },
        );

        swap_id
    }

    /// Complete the swap by providing the correct preimage
    /// 
    /// # Arguments
    /// * `swap_id` - The swap identifier
    /// * `preimage` - The secret that hashes to the stored hash_lock
    pub fn complete_swap(env: Env, swap_id: BytesN<32>, preimage: Bytes) {
        let mut atomic_swap: AtomicSwap = env.storage().instance()
            .get(&DataKey::Swap(swap_id.clone()))
            .unwrap_or_else(|| panic!("swap not found"));

        // Verify caller is participant
        let caller = env.current_contract_address();
        require!(caller == atomic_swap.participant, "only participant can complete swap");

        // Verify swap is pending
        require!(matches!(atomic_swap.status, SwapStatus::Pending), "swap not pending");

        // Verify timeout hasn't passed
        let current_ledger = env.ledger().sequence();
        require!(current_ledger <= atomic_swap.timeout_ledger, "swap timed out");

        // Verify preimage hash matches
        let computed_hash = env.crypto().sha256(&preimage);
        require!(computed_hash == atomic_swap.hash_lock, "invalid preimage");

        // Update swap state
        atomic_swap.status = SwapStatus::Completed;
        atomic_swap.preimage = Some(preimage.clone());
        env.storage().instance().set(&DataKey::Swap(swap_id.clone()), &atomic_swap);

        // In a real implementation, this would transfer the assets
        // For now, we just emit the completion event
        env.events().publish(
            symbol_short!("swap_completed"),
            SwapEvent {
                swap_id,
                status: SwapStatus::Completed,
                timestamp: env.ledger().timestamp(),
            },
        );
    }

    /// Refund the swap after timeout
    /// 
    /// # Arguments
    /// * `swap_id` - The swap identifier
    pub fn refund_swap(env: Env, swap_id: BytesN<32>) {
        let mut atomic_swap: AtomicSwap = env.storage().instance()
            .get(&DataKey::Swap(swap_id.clone()))
            .unwrap_or_else(|| panic!("swap not found"));

        // Verify caller is initiator
        let caller = env.current_contract_address();
        require!(caller == atomic_swap.initiator, "only initiator can refund swap");

        // Verify swap is pending
        require!(matches!(atomic_swap.status, SwapStatus::Pending), "swap not pending");

        // Verify timeout has passed
        let current_ledger = env.ledger().sequence();
        require!(current_ledger > atomic_swap.timeout_ledger, "swap not timed out yet");

        // Update swap state
        atomic_swap.status = SwapStatus::Refunded;
        env.storage().instance().set(&DataKey::Swap(swap_id.clone()), &atomic_swap);

        // In a real implementation, this would refund the assets
        // For now, we just emit the refund event
        env.events().publish(
            symbol_short!("swap_refunded"),
            SwapEvent {
                swap_id,
                status: SwapStatus::Refunded,
                timestamp: env.ledger().timestamp(),
            },
        );
    }

    /// Get swap details
    /// 
    /// # Arguments
    /// * `swap_id` - The swap identifier
    /// 
    /// # Returns
    /// AtomicSwap - The swap details
    pub fn get_swap(env: Env, swap_id: BytesN<32>) -> AtomicSwap {
        env.storage().instance()
            .get(&DataKey::Swap(swap_id))
            .unwrap_or_else(|| panic!("swap not found"))
    }

    /// Get all active swaps for a participant
    /// 
    /// # Arguments
    /// * `participant` - The participant address
    /// 
    /// # Returns
    /// Vec<BytesN<32>> - List of active swap IDs
    pub fn get_active_swaps(env: Env, participant: Address) -> Vec<BytesN<32>> {
        let mut active_swaps = Vec::new(&env);
        
        // In a real implementation, this would iterate through stored swaps
        // For now, return empty vector as placeholder
        active_swaps
    }

    /// Check if a swap can be completed
    /// 
    /// # Arguments
    /// * `swap_id` - The swap identifier
    /// 
    /// # Returns
    /// bool - True if swap can be completed
    pub fn can_complete(env: Env, swap_id: BytesN<32>) -> bool {
        let atomic_swap: AtomicSwap = env.storage().instance()
            .get(&DataKey::Swap(swap_id))
            .unwrap_or_else(|| panic!("swap not found"));

        let current_ledger = env.ledger().sequence();
        matches!(atomic_swap.status, SwapStatus::Pending) && current_ledger <= atomic_swap.timeout_ledger
    }

    /// Check if a swap can be refunded
    /// 
    /// # Arguments
    /// * `swap_id` - The swap identifier
    /// 
    /// # Returns
    /// bool - True if swap can be refunded
    pub fn can_refund(env: Env, swap_id: BytesN<32>) -> bool {
        let atomic_swap: AtomicSwap = env.storage().instance()
            .get(&DataKey::Swap(swap_id))
            .unwrap_or_else(|| panic!("swap not found"));

        let current_ledger = env.ledger().sequence();
        matches!(atomic_swap.status, SwapStatus::Pending) && current_ledger > atomic_swap.timeout_ledger
    }
}

// Helper macro for require statements
macro_rules! require {
    ($condition:expr, $error:expr) => {
        if !$condition {
            panic!("{}", $error);
        }
    };
}
