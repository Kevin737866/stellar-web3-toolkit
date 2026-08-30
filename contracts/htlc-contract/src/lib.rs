#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, Vec};

const DAY_IN_LEDGERS: u32 = 17280;

macro_rules! require {
    ($condition:expr, $error:expr) => {
        if !$condition {
            panic!("{}", $error);
        }
    };
}

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

#[contract]
pub struct HtlcContract;

#[contractimpl]
impl HtlcContract {
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

        // Generate unique swap ID by hashing hash_lock + ledger sequence
        let mut id_bytes = Bytes::new(&env);
        id_bytes.extend_from_array(&hash_lock.to_array());
        let seq_bytes = current_ledger.to_be_bytes();
        id_bytes.append(&mut Bytes::from_slice(&env, &seq_bytes));
        let swap_id: BytesN<32> = env.crypto().sha256(&id_bytes).into();

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

        env.storage().instance().set(&DataKey::Swap(swap_id.clone()), &atomic_swap);

        env.events().publish(
            ("swap_created", swap_id.clone()),
            (initiator, participant, initiator_amount, participant_amount),
        );

        swap_id
    }

    pub fn complete_swap(env: Env, swap_id: BytesN<32>, preimage: Bytes) {
        let mut atomic_swap: AtomicSwap = env
            .storage()
            .instance()
            .get(&DataKey::Swap(swap_id.clone()))
            .unwrap_or_else(|| panic!("swap not found"));

        let caller = env.current_contract_address();
        require!(
            caller == atomic_swap.participant,
            "only participant can complete swap"
        );
        require!(
            matches!(atomic_swap.status, SwapStatus::Pending),
            "swap not pending"
        );

        let current_ledger = env.ledger().sequence();
        require!(current_ledger <= atomic_swap.timeout_ledger, "swap timed out");

        let computed_hash: BytesN<32> = env.crypto().sha256(&preimage).into();
        require!(computed_hash == atomic_swap.hash_lock, "invalid preimage");

        atomic_swap.status = SwapStatus::Completed;
        atomic_swap.preimage = Some(preimage);
        env.storage()
            .instance()
            .set(&DataKey::Swap(swap_id.clone()), &atomic_swap);

        env.events()
            .publish(("swap_completed", swap_id), ());
    }

    pub fn refund_swap(env: Env, swap_id: BytesN<32>) {
        let mut atomic_swap: AtomicSwap = env
            .storage()
            .instance()
            .get(&DataKey::Swap(swap_id.clone()))
            .unwrap_or_else(|| panic!("swap not found"));

        let caller = env.current_contract_address();
        require!(
            caller == atomic_swap.initiator,
            "only initiator can refund swap"
        );
        require!(
            matches!(atomic_swap.status, SwapStatus::Pending),
            "swap not pending"
        );

        let current_ledger = env.ledger().sequence();
        require!(
            current_ledger > atomic_swap.timeout_ledger,
            "swap not timed out yet"
        );

        atomic_swap.status = SwapStatus::Refunded;
        env.storage()
            .instance()
            .set(&DataKey::Swap(swap_id.clone()), &atomic_swap);

        env.events().publish(("swap_refunded", swap_id), ());
    }

    pub fn get_swap(env: Env, swap_id: BytesN<32>) -> AtomicSwap {
        env.storage()
            .instance()
            .get(&DataKey::Swap(swap_id))
            .unwrap_or_else(|| panic!("swap not found"))
    }

    pub fn get_active_swaps(_env: Env, _participant: Address) -> Vec<BytesN<32>> {
        Vec::new(&_env)
    }

    pub fn can_complete(env: Env, swap_id: BytesN<32>) -> bool {
        let atomic_swap: AtomicSwap = env
            .storage()
            .instance()
            .get(&DataKey::Swap(swap_id))
            .unwrap_or_else(|| panic!("swap not found"));

        let current_ledger = env.ledger().sequence();
        matches!(atomic_swap.status, SwapStatus::Pending)
            && current_ledger <= atomic_swap.timeout_ledger
    }

    pub fn can_refund(env: Env, swap_id: BytesN<32>) -> bool {
        let atomic_swap: AtomicSwap = env
            .storage()
            .instance()
            .get(&DataKey::Swap(swap_id))
            .unwrap_or_else(|| panic!("swap not found"));

        let current_ledger = env.ledger().sequence();
        matches!(atomic_swap.status, SwapStatus::Pending)
            && current_ledger > atomic_swap.timeout_ledger
    }
}
