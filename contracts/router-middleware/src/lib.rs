#![no_std]

//! # router-middleware
//!
//! Pre/post call hook middleware for the stellar-router suite.
//! Supports rate limiting, call logging, and per-route fee configuration.
//!
//! ## Features
//! - Per-caller rate limiting (max calls per time window)
//! - Call event logging with timestamps
//! - Configurable per-route fees
//! - Admin-controlled hook enable/disable

use soroban_sdk::{contract, contractimpl, contracttype, contracterror, Address, Env, String, Symbol};

// ── Storage Keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    RateLimit(String, Address),  // (route, address) -> RateLimitState
    RouteConfig(String),        // route_name -> RouteConfig
    GlobalEnabled,
    TotalCalls,
    CircuitBreaker(String),     // route_name -> CircuitBreakerState
    CallLog(String),            // route_name -> Vec<CallLogEntry>
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimitState {
    /// Number of calls in current window
    pub calls_in_window: u32,
    /// Timestamp when window started
    pub window_start: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RouteConfig {
    /// Max calls per window (0 = unlimited)
    pub max_calls_per_window: u32,
    /// Window size in seconds
    pub window_seconds: u64,
    /// Whether this route is enabled
    pub enabled: bool,
    /// Circuit breaker failure threshold (0 = disabled)
    pub failure_threshold: u32,
    /// Circuit breaker recovery window in seconds
    pub recovery_window_seconds: u64,
    /// Max call log entries to keep (0 = disabled)
    pub log_retention: u32,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CircuitBreakerState {
    /// Number of consecutive failures
    pub failure_count: u32,
    /// Timestamp when circuit was opened
    pub opened_at: u64,
    /// Whether circuit is currently open
    pub is_open: bool,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CallLogEntry {
    /// The caller address
    pub caller: Address,
    /// Timestamp of the call
    pub timestamp: u64,
    /// Whether the call succeeded
    pub success: bool,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MiddlewareError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    RateLimitExceeded = 4,
    RouteDisabled = 5,
    MiddlewareDisabled = 6,
    InvalidConfig = 7,
    CircuitOpen = 8,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct RouterMiddleware;

#[contractimpl]
impl RouterMiddleware {
    /// Initialize middleware with an admin.
    ///
    /// Must be called exactly once. Sets the admin, enables middleware globally,
    /// and resets the total call counter to zero.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `admin` - The address that will have admin privileges over this middleware.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// * [`MiddlewareError::AlreadyInitialized`] — if the contract has already been initialized.
    pub fn initialize(env: Env, admin: Address) -> Result<(), MiddlewareError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(MiddlewareError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::GlobalEnabled, &true);
        env.storage().instance().set(&DataKey::TotalCalls, &0u64);
        Ok(())
    }

    /// Configure a route's middleware settings.
    ///
    /// Sets the rate-limit window and call cap for `route`, and whether the
    /// route is enabled. If `max_calls_per_window` is 0, rate limiting is
    /// disabled for that route. Caller must be the admin.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - The address initiating the call; must be the admin.
    /// * `route` - The route name to configure.
    /// * `max_calls_per_window` - Maximum allowed calls per time window (0 = unlimited).
    /// * `window_seconds` - Duration of the rate-limit window in seconds.
    /// * `enabled` - Whether this route should be enabled.
    /// * `failure_threshold` - Circuit breaker failure threshold (0 = disabled).
    /// * `recovery_window_seconds` - Circuit breaker recovery window in seconds.
    /// * `log_retention` - Maximum call log entries to keep (0 = disabled).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// * [`MiddlewareError::Unauthorized`] — if `caller` is not the admin.
    /// * [`MiddlewareError::InvalidConfig`] — if `window_seconds` is 0 while `max_calls_per_window` > 0.
    /// * [`MiddlewareError::NotInitialized`] — if the contract has not been initialized.
    pub fn configure_route(
        env: Env,
        caller: Address,
        route: String,
        max_calls_per_window: u32,
        window_seconds: u64,
        enabled: bool,
        failure_threshold: u32,
        recovery_window_seconds: u64,
        log_retention: u32,
    ) -> Result<(), MiddlewareError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        if window_seconds == 0 && max_calls_per_window > 0 {
            return Err(MiddlewareError::InvalidConfig);
        }

        let config = RouteConfig {
            max_calls_per_window,
            window_seconds,
            enabled,
            failure_threshold,
            recovery_window_seconds,
            log_retention,
        };
        env.storage().instance().set(&DataKey::RouteConfig(route), &config);
        Ok(())
    }

    /// Pre-call hook: validates rate limits and route status.
    ///
    /// Must be called before routing to a contract. Checks that middleware is
    /// globally enabled, that the specific route is enabled, and that the
    /// `caller` has not exceeded their rate limit for `route`. On success,
    /// increments the global call counter and emits a `pre_call` event.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - The address making the routed call.
    /// * `route` - The name of the route being called.
    ///
    /// # Returns
    /// `Ok(())` if the call is allowed to proceed.
    ///
    /// # Errors
    /// * [`MiddlewareError::MiddlewareDisabled`] — if middleware is globally disabled.
    /// * [`MiddlewareError::RouteDisabled`] — if the specific route is disabled.
    /// * [`MiddlewareError::RateLimitExceeded`] — if `caller` has exceeded the rate limit for `route`.
    /// * [`MiddlewareError::CircuitOpen`] — if the circuit breaker is open for the route.
    pub fn pre_call(
        env: Env,
        caller: Address,
        route: String,
    ) -> Result<(), MiddlewareError> {
        // Check global enable
        let enabled: bool = env
            .storage()
            .instance()
            .get(&DataKey::GlobalEnabled)
            .unwrap_or(true);
        if !enabled {
            return Err(MiddlewareError::MiddlewareDisabled);
        }

        // Check route config
        if let Some(config) = env
            .storage()
            .instance()
            .get::<DataKey, RouteConfig>(&DataKey::RouteConfig(route.clone()))
        {
            if !config.enabled {
                return Err(MiddlewareError::RouteDisabled);
            }

            // Check circuit breaker
            if config.failure_threshold > 0 {
                let cb_state: CircuitBreakerState = env
                    .storage()
                    .instance()
                    .get(&DataKey::CircuitBreaker(route.clone()))
                    .unwrap_or(CircuitBreakerState {
                        failure_count: 0,
                        opened_at: 0,
                        is_open: false,
                    });

                if cb_state.is_open {
                    let now = env.ledger().timestamp();
                    let recovery_elapsed = now >= cb_state.opened_at + config.recovery_window_seconds;
                    if !recovery_elapsed {
                        return Err(MiddlewareError::CircuitOpen);
                    }
                }
            }

            // Check rate limit
            if config.max_calls_per_window > 0 {
                let now = env.ledger().timestamp();
                let state: RateLimitState = env
                    .storage()
                    .instance()
                    .get(&DataKey::RateLimit(route.clone(), caller.clone()))
                    .unwrap_or(RateLimitState {
                        calls_in_window: 0,
                        window_start: now,
                    });

                // Check if window has elapsed
                let window_elapsed = now >= state.window_start + config.window_seconds;
                let calls = if window_elapsed { 0 } else { state.calls_in_window };
                let window_start = if window_elapsed { now } else { state.window_start };

                if calls >= config.max_calls_per_window {
                    return Err(MiddlewareError::RateLimitExceeded);
                }

                env.storage().instance().set(
                    &DataKey::RateLimit(route.clone(), caller.clone()),
                    &RateLimitState {
                        calls_in_window: calls + 1,
                        window_start,
                    },
                );
            }
        }

        // Increment global call counter
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCalls)
            .unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalCalls, &(total + 1));

        // Emit call event
        env.events().publish(
            (Symbol::new(&env, "pre_call"),),
            (caller.clone(), route.clone()),
        );

        Ok(())
    }

    /// Post-call hook: tracks failures and manages circuit breaker.
    ///
    /// Should be called after a routed contract call completes. Emits a
    /// `post_call` event with the caller, route name, and outcome. If the call
    /// failed and the route has a circuit breaker configured, increments the
    /// failure count and trips the circuit if the threshold is reached.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - The address that made the routed call.
    /// * `route` - The name of the route that was called.
    /// * `success` - `true` if the call succeeded, `false` if it failed.
    pub fn post_call(env: Env, caller: Address, route: String, success: bool) {
        env.events().publish(
            (Symbol::new(&env, "post_call"),),
            (caller.clone(), route.clone(), success),
        );

        // Log the call if retention is enabled
        if let Some(config) = env
            .storage()
            .instance()
            .get::<DataKey, RouteConfig>(&DataKey::RouteConfig(route.clone()))
        {
            if config.log_retention > 0 {
                let mut log: Vec<CallLogEntry> = env
                    .storage()
                    .instance()
                    .get(&DataKey::CallLog(route.clone()))
                    .unwrap_or(Vec::new(&env));

                let entry = CallLogEntry {
                    caller: caller.clone(),
                    timestamp: env.ledger().timestamp(),
                    success,
                };
                log.push_back(entry);

                if log.len() > config.log_retention {
                    // Remove oldest entry (ring buffer)
                    let mut new_log = Vec::new(&env);
                    for i in 1..log.len() {
                        new_log.push_back(log.get(i).unwrap());
                    }
                    log = new_log;
                }

                env.storage().instance().set(&DataKey::CallLog(route), &log);
            }
        }

        if !success {
            if let Some(config) = env
                .storage()
                .instance()
                .get::<DataKey, RouteConfig>(&DataKey::RouteConfig(route.clone()))
            {
                if config.failure_threshold > 0 {
                    let mut cb_state: CircuitBreakerState = env
                        .storage()
                        .instance()
                        .get(&DataKey::CircuitBreaker(route.clone()))
                        .unwrap_or(CircuitBreakerState {
                            failure_count: 0,
                            opened_at: 0,
                            is_open: false,
                        });

                    cb_state.failure_count += 1;

                    if cb_state.failure_count >= config.failure_threshold {
                        cb_state.is_open = true;
                        cb_state.opened_at = env.ledger().timestamp();
                        env.events().publish(
                            (Symbol::new(&env, "circuit_opened"),),
                            (route.clone(), cb_state.failure_count),
                        );
                    }

                    env.storage()
                        .instance()
                        .set(&DataKey::CircuitBreaker(route), &cb_state);
                }
            }
        }
    }

    /// Enable or disable all middleware globally.
    ///
    /// When disabled, `pre_call` will return
    /// [`MiddlewareError::MiddlewareDisabled`] for every route. Caller must be
    /// the admin.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - The address initiating the call; must be the admin.
    /// * `enabled` - `true` to enable middleware, `false` to disable it.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// * [`MiddlewareError::Unauthorized`] — if `caller` is not the admin.
    /// * [`MiddlewareError::NotInitialized`] — if the contract has not been initialized.
    pub fn set_global_enabled(
        env: Env,
        caller: Address,
        enabled: bool,
    ) -> Result<(), MiddlewareError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::GlobalEnabled, &enabled);
        Ok(())
    }

    /// Get total calls processed.
    ///
    /// Returns the cumulative count of calls that have passed through
    /// `pre_call` since the contract was initialized.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    ///
    /// # Returns
    /// The total number of pre-call invocations.
    pub fn total_calls(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::TotalCalls).unwrap_or(0)
    }
    /// Get the call log for a route.
    ///
    /// Returns the list of recent call log entries for `route`, up to the
    /// configured retention limit. Entries are in chronological order (oldest first).
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `route` - The route name to retrieve logs for.
    ///
    /// # Returns
    /// A [`Vec<CallLogEntry>`] of call log entries.
    pub fn get_call_log(env: Env, route: String) -> Vec<CallLogEntry> {
        env.storage()
            .instance()
            .get(&DataKey::CallLog(route))
            .unwrap_or(Vec::new(&env))
    }
    /// Get rate limit state for a caller on a specific route.
    ///
    /// Returns the current [`RateLimitState`] for `caller` on `route`, which includes the
    /// number of calls made in the current window and when the window started.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `route` - The route name to look up.
    /// * `caller` - The address whose rate limit state to retrieve.
    ///
    /// # Returns
    /// `Some(`[`RateLimitState`]`)` if the caller has made at least one call on this route,
    /// `None` otherwise.
    pub fn rate_limit_state(env: Env, route: String, caller: Address) -> Option<RateLimitState> {
        env.storage().instance().get(&DataKey::RateLimit(route, caller))
    }

    /// Get config for a route.
    ///
    /// Returns the [`RouteConfig`] for `route` if one has been set via
    /// `configure_route`.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `route` - The route name to look up.
    ///
    /// # Returns
    /// `Some(`[`RouteConfig`]`)` if a config exists for `route`, `None` otherwise.
    pub fn route_config(env: Env, route: String) -> Option<RouteConfig> {
        env.storage().instance().get(&DataKey::RouteConfig(route))
    }

    /// Get current admin.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    ///
    /// # Returns
    /// The [`Address`] of the current admin.
    ///
    /// # Errors
    /// * [`MiddlewareError::NotInitialized`] — if the contract has not been initialized.
    pub fn admin(env: Env) -> Result<Address, MiddlewareError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(MiddlewareError::NotInitialized)
    }

    /// Reset circuit breaker for a route.
    ///
    /// Manually resets the circuit breaker state for a route, clearing the
    /// failure count and closing the circuit. Caller must be the admin.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - The address initiating the call; must be the admin.
    /// * `route` - The route name whose circuit breaker should be reset.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// * [`MiddlewareError::Unauthorized`] — if `caller` is not the admin.
    /// * [`MiddlewareError::NotInitialized`] — if the contract has not been initialized.
    pub fn reset_circuit_breaker(
        env: Env,
        caller: Address,
        route: String,
    ) -> Result<(), MiddlewareError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        let reset_state = CircuitBreakerState {
            failure_count: 0,
            opened_at: 0,
            is_open: false,
        };
        env.storage()
            .instance()
            .set(&DataKey::CircuitBreaker(route), &reset_state);
        Ok(())
    }

    /// Transfer admin to a new address.
    ///
    /// Replaces the current admin with `new_admin`. The `current` address must
    /// authenticate and must be the existing admin.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `current` - The current admin address; must authenticate.
    /// * `new_admin` - The address that will become the new admin.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// * [`MiddlewareError::Unauthorized`] — if `current` is not the admin.
    /// * [`MiddlewareError::NotInitialized`] — if the contract has not been initialized.
    pub fn transfer_admin(env: Env, current: Address, new_admin: Address) -> Result<(), MiddlewareError> {
        current.require_auth();
        Self::require_admin(&env, &current)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), MiddlewareError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(MiddlewareError::NotInitialized)?;
        if &admin != caller {
            return Err(MiddlewareError::Unauthorized);
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger}, Env, String};

    fn setup() -> (Env, Address, RouterMiddlewareClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RouterMiddleware);
        let client = RouterMiddlewareClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_pre_call_no_config_passes() {
        let (env, _, client) = setup();
        let caller = Address::generate(&env);
        let route = String::from_str(&env, "oracle/get_price");
        let result = client.try_pre_call(&caller, &route);
        assert!(result.is_ok());
        assert_eq!(client.total_calls(), 1);
    }

    #[test]
    fn test_rate_limit_enforced() {
        let (env, admin, client) = setup();
        let route = String::from_str(&env, "oracle/get_price");
        // max 2 calls per 60s window
        client.configure_route(&admin, &route, &2, &60, &true, &0, &0, &0);

        let caller = Address::generate(&env);
        client.pre_call(&caller, &route);
        client.pre_call(&caller, &route);
        let result = client.try_pre_call(&caller, &route);
        assert_eq!(result, Err(Ok(MiddlewareError::RateLimitExceeded)));
    }

    #[test]
    fn test_rate_limit_resets_after_window() {
        let (env, admin, client) = setup();
        let route = String::from_str(&env, "oracle/get_price");
        client.configure_route(&admin, &route, &1, &60, &true, &0, &0, &0);

        let caller = Address::generate(&env);
        client.pre_call(&caller, &route);
        // Advance past window
        env.ledger().with_mut(|l| l.timestamp += 61);
        let result = client.try_pre_call(&caller, &route);
        assert!(result.is_ok());
    }

    #[test]
    fn test_disabled_route_blocked() {
        let (env, admin, client) = setup();
        let route = String::from_str(&env, "oracle/get_price");
        client.configure_route(&admin, &route, &0, &0, &false, &0, &0, &0);
        let caller = Address::generate(&env);
        let result = client.try_pre_call(&caller, &route);
        assert_eq!(result, Err(Ok(MiddlewareError::RouteDisabled)));
    }

    #[test]
    fn test_global_disable_blocks_all() {
        let (env, admin, client) = setup();
        client.set_global_enabled(&admin, &false);
        let caller = Address::generate(&env);
        let route = String::from_str(&env, "any/route");
        let result = client.try_pre_call(&caller, &route);
        assert_eq!(result, Err(Ok(MiddlewareError::MiddlewareDisabled)));
    }

    #[test]
    fn test_unauthorized_configure_fails() {
        let (env, _admin, client) = setup();
        let attacker = Address::generate(&env);
        let route = String::from_str(&env, "oracle/get_price");
        let result = client.try_configure_route(&attacker, &route, &10, &60, &true, &0, &0, &0);
        assert_eq!(result, Err(Ok(MiddlewareError::Unauthorized)));
    }

    #[test]
    fn test_post_call_succeeds() {
        let (env, _, client) = setup();
        let caller = Address::generate(&env);
        let route = String::from_str(&env, "oracle/get_price");
        
        // post_call should succeed with both true and false outcomes
        client.post_call(&caller, &route, &true);
        client.post_call(&caller, &route, &false);
    }

    #[test]
    fn test_rate_limit_isolated_per_route() {
        let (env, admin, client) = setup();
        let route_a = String::from_str(&env, "oracle/price");
        let route_b = String::from_str(&env, "vault/deposit");
        // route_a: 10 calls per minute, route_b: 5 calls per minute
        client.configure_route(&admin, &route_a, &10, &60, &true, &0, &0, &0);
        client.configure_route(&admin, &route_b, &5, &60, &true, &0, &0, &0);

        let caller = Address::generate(&env);
        // Make 4 calls on route_a — drains route_a counter to 4
        for _ in 0..4 {
            client.pre_call(&caller, &route_a);
        }
        // First call on route_b should succeed (independent counter starts at 0)
        assert!(client.try_pre_call(&caller, &route_b).is_ok());
        // Exhaust route_b (4 more calls → total 5 on route_b)
        for _ in 0..4 {
            client.pre_call(&caller, &route_b);
        }
        // route_b is now at its limit; route_a still has headroom
        assert_eq!(
            client.try_pre_call(&caller, &route_b),
            Err(Ok(MiddlewareError::RateLimitExceeded))
        );
        assert!(client.try_pre_call(&caller, &route_a).is_ok());
    }

    #[test]
    fn test_total_calls_not_incremented_on_rejected_pre_call() {
        let (env, admin, client) = setup();
        let route = String::from_str(&env, "oracle/get_price");
        client.configure_route(&admin, &route, &1, &60, &true, &0, &0, &0);
        
        let caller = Address::generate(&env);
        client.pre_call(&caller, &route);                     // passes, total = 1
        assert_eq!(client.total_calls(), 1);
        
        let _ = client.try_pre_call(&caller, &route);         // rejected (rate limit)
        assert_eq!(client.total_calls(), 1);                  // must still be 1
    }

    #[test]
    fn test_admin_getter() {
        let (env, admin, client) = setup();
        let retrieved_admin = client.admin();
        assert_eq!(retrieved_admin, admin);
    }

    #[test]
    fn test_transfer_admin() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin);
        assert_eq!(client.admin(), new_admin);
    }

    #[test]
    fn test_unauthorized_transfer_admin_fails() {
        let (env, _admin, client) = setup();
        let attacker = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let result = client.try_transfer_admin(&attacker, &new_admin);
        assert_eq!(result, Err(Ok(MiddlewareError::Unauthorized)));
    }

    #[test]
    fn test_old_admin_locked_out_after_transfer() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin);

        // old admin should no longer be able to configure routes
        let route = String::from_str(&env, "oracle/get_price");
        let result = client.try_configure_route(&admin, &route, &10, &60, &true, &0, &0, &0);
        assert_eq!(result, Err(Ok(MiddlewareError::Unauthorized)));

        // new admin should be able to configure routes
        assert!(
            client
                .try_configure_route(&new_admin, &route, &10, &60, &true, &0, &0, &0)
                .is_ok()
        );
    }
}
