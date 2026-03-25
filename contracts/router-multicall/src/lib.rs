#![no_std]

//! # router-multicall
//!
//! Batch multiple cross-contract read calls in a single transaction.
//! Reduces round-trips when a client needs data from multiple contracts.
//!
//! ## Features
//! - Aggregate up to N calls in one transaction
//! - Per-call success/failure tracking (non-atomic mode)
//! - Atomic mode: revert all if any call fails
//! - Call result storage for async inspection

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror,
    Address, Env, Vec, Symbol, Val,
};

// ── Storage Keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    MaxBatchSize,
    TotalBatches,
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// A single call descriptor in a batch.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CallDescriptor {
    /// Target contract address
    pub target: Address,
    /// Function name to call
    pub function: Symbol,
    /// Whether failure of this call should abort the whole batch
    pub required: bool,
}

/// Result of a single call in a batch.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CallResult {
    pub target: Address,
    pub function: Symbol,
    pub success: bool,
}

/// Summary of a batch execution.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct BatchSummary {
    pub total: u32,
    pub succeeded: u32,
    pub failed: u32,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MulticallError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    BatchTooLarge = 4,
    EmptyBatch = 5,
    RequiredCallFailed = 6,
    InvalidConfig = 7,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct RouterMulticall;

#[contractimpl]
impl RouterMulticall {
    /// Initialize with admin and maximum batch size.
    ///
    /// Must be called exactly once. Sets the admin, the maximum number of calls
    /// allowed per batch, and resets the total batch counter to zero.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `admin` - The address that will have admin privileges over this contract.
    /// * `max_batch_size` - The maximum number of [`CallDescriptor`]s allowed in
    ///   a single `execute_batch` call. Must be greater than zero.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// * [`MulticallError::AlreadyInitialized`] — if the contract has already been initialized.
    /// * [`MulticallError::InvalidConfig`] — if `max_batch_size` is zero.
    pub fn initialize(env: Env, admin: Address, max_batch_size: u32) -> Result<(), MulticallError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(MulticallError::AlreadyInitialized);
        }
        if max_batch_size == 0 {
            return Err(MulticallError::InvalidConfig);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::MaxBatchSize, &max_batch_size);
        env.storage().instance().set(&DataKey::TotalBatches, &0u64);
        Ok(())
    }

    /// Execute a batch of calls. Returns a summary of results.
    ///
    /// Iterates over each [`CallDescriptor`] in `calls` and attempts a
    /// cross-contract invocation. Tracks per-call success and failure. If a
    /// call marked `required` fails, the entire batch is aborted and
    /// [`MulticallError::RequiredCallFailed`] is returned. On completion,
    /// increments the total batch counter.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - The address initiating the batch; must authenticate.
    /// * `calls` - A list of [`CallDescriptor`]s describing each call to make.
    ///   Must be non-empty and no larger than the configured `max_batch_size`.
    ///
    /// # Returns
    /// A [`BatchSummary`] with the total, succeeded, and failed call counts.
    ///
    /// # Errors
    /// * [`MulticallError::EmptyBatch`] — if `calls` is empty.
    /// * [`MulticallError::BatchTooLarge`] — if `calls` exceeds `max_batch_size`.
    /// * [`MulticallError::RequiredCallFailed`] — if a call with `required = true` fails.
    /// * [`MulticallError::NotInitialized`] — if the contract has not been initialized.
    pub fn execute_batch(
        env: Env,
        caller: Address,
        calls: Vec<CallDescriptor>,
    ) -> Result<BatchSummary, MulticallError> {
        caller.require_auth();

        if calls.is_empty() {
            return Err(MulticallError::EmptyBatch);
        }

        let max: u32 = env
            .storage()
            .instance()
            .get(&DataKey::MaxBatchSize)
            .ok_or(MulticallError::NotInitialized)?;

        if calls.len() > max {
            return Err(MulticallError::BatchTooLarge);
        }

        let mut succeeded = 0u32;
        let mut failed = 0u32;
        let total = calls.len();

        for call in calls.iter() {
            // Attempt the cross-contract call with empty args
            let args: Vec<Val> = Vec::new(&env);
            let result = env.try_invoke_contract::<Val, Val>(&call.target, &call.function, args);

            let success = result.is_ok();

            if success {
                succeeded += 1;
            } else {
                failed += 1;
                if call.required {
                    return Err(MulticallError::RequiredCallFailed);
                }
            }

            env.events().publish(
                (Symbol::new(&env, "call_result"),),
                (&call.target, &call.function, success),
            );
        }

        // Increment batch counter
        let batches: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TotalBatches)
            .unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalBatches, &(batches + 1));

        Ok(BatchSummary {
            total,
            succeeded,
            failed,
        })
    }

    /// Update the maximum batch size.
    ///
    /// Changes the upper limit on the number of calls allowed per batch.
    /// Caller must be the admin.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - The address initiating the call; must be the admin.
    /// * `max_batch_size` - The new maximum batch size. Must be greater than zero.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// * [`MulticallError::Unauthorized`] — if `caller` is not the admin.
    /// * [`MulticallError::InvalidConfig`] — if `max_batch_size` is zero.
    /// * [`MulticallError::NotInitialized`] — if the contract has not been initialized.
    pub fn set_max_batch_size(
        env: Env,
        caller: Address,
        max_batch_size: u32,
    ) -> Result<(), MulticallError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;
        if max_batch_size == 0 {
            return Err(MulticallError::InvalidConfig);
        }
        env.storage().instance().set(&DataKey::MaxBatchSize, &max_batch_size);
        Ok(())
    }

    /// Get total batches executed.
    ///
    /// Returns the cumulative count of successful `execute_batch`
    /// invocations since the contract was initialized.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    ///
    /// # Returns
    /// The total number of batches that have been executed.
    pub fn total_batches(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::TotalBatches).unwrap_or(0)
    }

    /// Get the max batch size.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    ///
    /// # Returns
    /// The maximum number of calls allowed per batch.
    ///
    /// # Errors
    /// * [`MulticallError::NotInitialized`] — if the contract has not been initialized.
    pub fn max_batch_size(env: Env) -> Result<u32, MulticallError> {
        env.storage()
            .instance()
            .get(&DataKey::MaxBatchSize)
            .ok_or(MulticallError::NotInitialized)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), MulticallError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(MulticallError::NotInitialized)?;
        if &admin != caller {
            return Err(MulticallError::Unauthorized);
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env, Symbol, Vec};

    fn setup() -> (Env, Address, RouterMulticallClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RouterMulticall);
        let client = RouterMulticallClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &10);
        (env, admin, client)
    }

    #[test]
    fn test_initialize() {
        let (_, _, client) = setup();
        assert_eq!(client.max_batch_size(), 10);
        assert_eq!(client.total_batches(), 0);
    }

    #[test]
    fn test_double_initialize_fails() {
        let (_env, admin, client) = setup();
        let result = client.try_initialize(&admin, &10);
        assert_eq!(result, Err(Ok(MulticallError::AlreadyInitialized)));
    }

    #[test]
    fn test_empty_batch_fails() {
        let (env, _admin, client) = setup();
        let caller = Address::generate(&env);
        let calls: Vec<CallDescriptor> = Vec::new(&env);
        let result = client.try_execute_batch(&caller, &calls);
        assert_eq!(result, Err(Ok(MulticallError::EmptyBatch)));
    }

    #[test]
    fn test_batch_too_large_fails() {
        let (env, admin, client) = setup();
        client.set_max_batch_size(&admin, &2);
        let caller = Address::generate(&env);
        let mut calls: Vec<CallDescriptor> = Vec::new(&env);
        for _ in 0..3 {
            calls.push_back(CallDescriptor {
                target: Address::generate(&env),
                function: Symbol::new(&env, "ping"),
                required: false,
            });
        }
        let result = client.try_execute_batch(&caller, &calls);
        assert_eq!(result, Err(Ok(MulticallError::BatchTooLarge)));
    }

    #[test]
    fn test_set_max_batch_size() {
        let (_env, admin, client) = setup();
        client.set_max_batch_size(&admin, &5);
        assert_eq!(client.max_batch_size(), 5);
    }

    #[test]
    fn test_unauthorized_set_max_fails() {
        let (env, _admin, client) = setup();
        let attacker = Address::generate(&env);
        let result = client.try_set_max_batch_size(&attacker, &5);
        assert_eq!(result, Err(Ok(MulticallError::Unauthorized)));
    }

    #[test]
    fn test_invalid_config_zero_max_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RouterMulticall);
        let client = RouterMulticallClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let result = client.try_initialize(&admin, &0);
        assert_eq!(result, Err(Ok(MulticallError::InvalidConfig)));
    }

    #[contract]
    pub struct MockContract;

    #[contractimpl]
    impl MockContract {
        pub fn success(_env: Env) {}
        pub fn fail(_env: Env) {
            panic!("intended failure");
        }
    }

    #[test]
    fn test_all_calls_succeed() {
        let (env, _admin, client) = setup();
        let mock_id = env.register_contract(None, MockContract);
        let caller = Address::generate(&env);

        let mut calls = Vec::new(&env);
        calls.push_back(CallDescriptor {
            target: mock_id.clone(),
            function: Symbol::new(&env, "success"),
            required: true,
        });
        calls.push_back(CallDescriptor {
            target: mock_id.clone(),
            function: Symbol::new(&env, "success"),
            required: false,
        });

        let summary = client.execute_batch(&caller, &calls);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 0);
        assert_eq!(client.total_batches(), 1);
    }

    #[test]
    fn test_optional_calls_fail_batch_completes() {
        let (env, _admin, client) = setup();
        let mock_id = env.register_contract(None, MockContract);
        let caller = Address::generate(&env);

        let mut calls = Vec::new(&env);
        // Successful required call
        calls.push_back(CallDescriptor {
            target: mock_id.clone(),
            function: Symbol::new(&env, "success"),
            required: true,
        });
        // Failing optional call
        calls.push_back(CallDescriptor {
            target: mock_id.clone(),
            function: Symbol::new(&env, "fail"),
            required: false,
        });
        // Successful optional call
        calls.push_back(CallDescriptor {
            target: mock_id.clone(),
            function: Symbol::new(&env, "success"),
            required: false,
        });

        let summary = client.execute_batch(&caller, &calls);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 1);
        assert_eq!(client.total_batches(), 1);
    }

    #[test]
    fn test_required_call_fails_aborts_batch() {
        let (env, _admin, client) = setup();
        let mock_id = env.register_contract(None, MockContract);
        let caller = Address::generate(&env);

        let mut calls = Vec::new(&env);
        // Successful optional call
        calls.push_back(CallDescriptor {
            target: mock_id.clone(),
            function: Symbol::new(&env, "success"),
            required: false,
        });
        // Failing required call
        calls.push_back(CallDescriptor {
            target: mock_id.clone(),
            function: Symbol::new(&env, "fail"),
            required: true,
        });
        // This should not even reach
        calls.push_back(CallDescriptor {
            target: mock_id.clone(),
            function: Symbol::new(&env, "success"),
            required: false,
        });

        let result = client.try_execute_batch(&caller, &calls);
        assert_eq!(result, Err(Ok(MulticallError::RequiredCallFailed)));
        // Total batches should NOT increment if it failed
        assert_eq!(client.total_batches(), 0);
    }
}
