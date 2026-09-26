#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, Vec};
use soroban_ttl::{extend_instance, TtlPolicy};

const DAY_IN_LEDGERS: u32 = 17280;

/// A swap is only actionable until its timeout, and the counterparty may come back
/// long after it was opened, so swap state is kept alive on a generous policy.
const SWAP_TTL: TtlPolicy = TtlPolicy::LONG_LIVED;

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

/// Persist swap state and keep its storage entry alive.
///
/// Writing and extending are deliberately paired: every mutation is proof that the
/// swap is still in use, so it is the natural moment to pay for another TTL window.
fn store_swap(env: &Env, swap_id: &BytesN<32>, swap: &AtomicSwap) {
    env.storage()
        .instance()
        .set(&DataKey::Swap(swap_id.clone()), swap);
    extend_instance(env, SWAP_TTL);
}

/// Read swap state and keep its storage entry alive.
///
/// The read paths extend too: a participant polling `get_swap` or `can_complete`
/// is still relying on that entry, and an archived swap would be unusable until
/// someone paid for a restore.
fn load_swap(env: &Env, swap_id: &BytesN<32>) -> AtomicSwap {
    let swap: AtomicSwap = env
        .storage()
        .instance()
        .get(&DataKey::Swap(swap_id.clone()))
        .unwrap_or_else(|| panic!("swap not found"));
    extend_instance(env, SWAP_TTL);
    swap
}

#[contractimpl]
impl HtlcContract {
    // The argument list *is* the contract interface for creating a swap; there is no
    // sensible parameter object to collapse it into.
    #[allow(clippy::too_many_arguments)]
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
        id_bytes.append(&Bytes::from_slice(&env, &seq_bytes));
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

        store_swap(&env, &swap_id, &atomic_swap);

        env.events().publish(
            ("swap_created", swap_id.clone()),
            (initiator, participant, initiator_amount, participant_amount),
        );

        swap_id
    }

    pub fn complete_swap(env: Env, swap_id: BytesN<32>, preimage: Bytes) {
        let mut atomic_swap = load_swap(&env, &swap_id);

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
        require!(
            current_ledger <= atomic_swap.timeout_ledger,
            "swap timed out"
        );

        let computed_hash: BytesN<32> = env.crypto().sha256(&preimage).into();
        require!(computed_hash == atomic_swap.hash_lock, "invalid preimage");

        atomic_swap.status = SwapStatus::Completed;
        atomic_swap.preimage = Some(preimage);
        store_swap(&env, &swap_id, &atomic_swap);

        env.events().publish(("swap_completed", swap_id), ());
    }

    pub fn refund_swap(env: Env, swap_id: BytesN<32>) {
        let mut atomic_swap = load_swap(&env, &swap_id);

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
        store_swap(&env, &swap_id, &atomic_swap);

        env.events().publish(("swap_refunded", swap_id), ());
    }

    pub fn get_swap(env: Env, swap_id: BytesN<32>) -> AtomicSwap {
        load_swap(&env, &swap_id)
    }

    pub fn get_active_swaps(_env: Env, _participant: Address) -> Vec<BytesN<32>> {
        Vec::new(&_env)
    }

    pub fn can_complete(env: Env, swap_id: BytesN<32>) -> bool {
        let atomic_swap = load_swap(&env, &swap_id);

        let current_ledger = env.ledger().sequence();
        matches!(atomic_swap.status, SwapStatus::Pending)
            && current_ledger <= atomic_swap.timeout_ledger
    }

    pub fn can_refund(env: Env, swap_id: BytesN<32>) -> bool {
        let atomic_swap = load_swap(&env, &swap_id);

        let current_ledger = env.ledger().sequence();
        matches!(atomic_swap.status, SwapStatus::Pending)
            && current_ledger > atomic_swap.timeout_ledger
    }
}

#[cfg(test)]
mod ttl_tests {
    use super::*;
    use soroban_sdk::testutils::storage::Instance as _;
    use soroban_sdk::testutils::{Address as _, Ledger as _};

    fn deploy() -> (Env, Address) {
        let env = Env::default();
        let id = env.register_contract(None, HtlcContract);
        (env, id)
    }

    fn instance_ttl(env: &Env, id: &Address) -> u32 {
        env.as_contract(id, || env.storage().instance().get_ttl())
    }

    fn open_swap(env: &Env, id: &Address) -> BytesN<32> {
        let participant = Address::generate(env);
        let asset = Address::generate(env);
        let hash_lock = BytesN::from_array(env, &[3u8; 32]);
        HtlcContractClient::new(env, id).create_swap(
            &participant,
            &hash_lock,
            &asset,
            &asset,
            &1_000,
            &1_000,
            &24,
        )
    }

    #[test]
    fn creating_a_swap_pushes_the_instance_ttl_out() {
        let (env, id) = deploy();
        let before = instance_ttl(&env, &id);

        open_swap(&env, &id);

        let after = instance_ttl(&env, &id);
        assert!(
            after >= SWAP_TTL.extend_to.saturating_sub(1),
            "swap state should be kept alive to at least {} ledgers, got {after}",
            SWAP_TTL.extend_to
        );
        assert!(after > before, "ttl should have grown: {before} -> {after}");
    }

    #[test]
    fn reading_a_swap_revives_an_aged_entry() {
        let (env, id) = deploy();
        let swap_id = open_swap(&env, &id);

        // Let the swap age until its entry sits inside the extension threshold.
        let full = instance_ttl(&env, &id);
        let aged_to = SWAP_TTL.threshold;
        env.ledger().with_mut(|li| {
            li.sequence_number = li.sequence_number.saturating_add(full - aged_to);
        });
        assert_eq!(aged_to, instance_ttl(&env, &id));

        // A read is still a dependency on that entry, so it must renew it.
        let client = HtlcContractClient::new(&env, &id);
        assert_eq!(SwapStatus::Pending, client.get_swap(&swap_id).status);

        let after = instance_ttl(&env, &id);
        assert!(
            after >= SWAP_TTL.extend_to.saturating_sub(1),
            "get_swap should have revived the entry, ttl was {after}"
        );
    }

    #[test]
    fn a_timed_out_swap_is_still_refundable_after_a_long_dormant_period() {
        let (env, id) = deploy();
        let swap_id = open_swap(&env, &id);
        let client = HtlcContractClient::new(&env, &id);
        assert!(client.can_complete(&swap_id));

        // Sit on the swap for far longer than its timeout. The TTL policy keeps the
        // entry readable, so the initiator can still come back and reclaim funds
        // instead of the state having been silently archived.
        env.ledger().with_mut(|li| {
            li.sequence_number = li.sequence_number.saturating_add(500_000);
        });
        assert!(!client.can_complete(&swap_id));
        assert!(client.can_refund(&swap_id));

        client.refund_swap(&swap_id);
        assert_eq!(SwapStatus::Refunded, client.get_swap(&swap_id).status);
    }
}
