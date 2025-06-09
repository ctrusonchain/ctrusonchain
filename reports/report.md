# Introduction

A time-boxed security review of the **Pnp Exchange** protocol was done by **ctrusonchain**, with a focus on the security aspects of the application's implementation.

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource, and expertise-bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs, and on-chain monitoring are strongly recommended.

# About **PnP Exchange**

_PNP Exchange is a protocol building on the frontier of info finance by enabling permissionless prediction markets. It lets users create a prediction market out of any question and make it instantly tradable._

# Severity classification

| Severity               | Impact: High | Impact: Medium | Impact: Low |
| ---------------------- | ------------ | -------------- | ----------- |
| **Likelihood: High**   | High         | High           | Medium      |
| **Likelihood: Medium** | High         | Medium         | Low         |
| **Likelihood: Low**    | Medium       | Low            | Low         |

**Impact** - the technical, economic, and reputation damage of a successful attack

**Likelihood** - the chance that a particular vulnerability gets discovered and exploited

**Severity** - the overall criticality of the risk

# Security Assessment Summary
**_review commit hash_ - [b7b0a33c6ce5ca391aabdbaa7313f3167efc4074](https://github.com/pnp-protocol/pnp_protocol_solana/commit/b7b0a33c6ce5ca391aabdbaa7313f3167efc4074)**

### Scope

The following smart contracts were in scope of the audit:

- `src/*`

The following number of issues were found, categorized by their severity:

- Critical & High: 3 issues
- Medium: 3 issues
- Low: 3 issues

## Executive Summary

| **Metric** | **Value** |
|------------|-----------|
| **Total Findings** | 9 |
| **High** | 3 |
| **Medium** | 3 |
| **Low** | 3 |

---

## 📊 Findings Overview

| ID | Title | Severity |
|---|---|---|
| H-01 | Missing Collateral Token Mint Validation |  High |
| H-02 | First-Come-First-Serve Advantage in Position Redemption |  High |
| H-03 | Double Fee Extraction and Excessive Market Reserve Allocation |  High |
| M-01 | Unnecessary Token Account Creation During Market Settlement |  Medium |
| M-02 | Market creators can farm rent sol |  Medium |
| M-03 | Missing Slippage Protection in Token Minting |  Medium |
| L-01 | Stale Getter Instructions Causing Denial of Service |  Low |
| L-02 | Missing Admin Transfer Functionality |  Low |
| L-03 | Missing Protocol Pause Functionality |  Low |


---

# [H-01] : Missing Collateral Token Mint Validation

## Summary
**Location**: `mint_decision_tokens.rs` lines 165-186

The contract lacks proper validation for the collateral token mint, allowing attackers to provide any arbitrary token mint as collateral, including worthless or fake tokens.

## Description

In the `MintDecisionTokens` account structure, the collateral token mint and related accounts are defined without proper constraints:

```rust
/// Market's collateral token vault
#[account(
    mut,
    associated_token::mint = collateral_token_mint,
    associated_token::authority = market,
)]
pub market_reserve_vault: Box<InterfaceAccount<'info, TokenAccount>>,

/// Collateral token mint account
pub collateral_token_mint: Box<InterfaceAccount<'info, Mint>>,

/// Buyer's collateral token account
#[account(
    mut,
    associated_token::mint = collateral_token_mint,
    associated_token::authority = buyer,
)]
pub buyer_collateral_token_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**Vulnerability Details:**

1. **No Mint Validation**: The `collateral_token_mint` field has no constraints to validate it against the global configuration's approved collateral token
2. **Arbitrary Token Acceptance**: Attackers can provide any worthless tokens that they control and mint legitimate yes and no mints in case of minting decision tokens, exploits varies in rest two ixns.
3. **Associated Token Account Spoofing**: The `market_reserve_vault` and `buyer_collateral_token_account` will be created/validated for the spoofed mint

**Attack Scenario:**
1. Attacker creates a worthless token mint with large supply
2. Attacker calls `mint_decision_tokens` with their fake collateral token
3. Attacker transfers worthless tokens but receives legitimate decision tokens
4. Actual market's collateral token acccount never really recieves tokens, yet attacker walks away with decision tokens

## Recommendation

Add proper validation constraints to ensure the collateral token mint matches the globally configured collateral token:

```rust
/// Market's collateral token vault
#[account(
    mut,
    associated_token::mint = collateral_token_mint,
    associated_token::authority = market,
)]
pub market_reserve_vault: Box<InterfaceAccount<'info, TokenAccount>>,

/// Collateral token mint account
#[account(
    constraint = collateral_token_mint.key() == global_config.collateral_token_mint @ MintDecisionTokensError::InvalidCollateralMint,
)]
pub collateral_token_mint: Box<InterfaceAccount<'info, Mint>>,

/// Buyer's collateral token account
#[account(
    mut,
    associated_token::mint = collateral_token_mint,
    associated_token::authority = buyer,
)]
pub buyer_collateral_token_account: Box<InterfaceAccount<'info, TokenAccount>>,
```
This fix ensures that only the globally configured collateral token can be used across all markets, preventing token spoofing attacks and maintaining the integrity of the prediction market system.

# [H-02] : First-Come-First-Serve Advantage in Position Redemption

## Summary
**Location**: `mint_decision_tokens.rs` lines 519-530

The position redemption mechanism creates an unfair first-come-first-serve advantage where early redeemers receive disproportionately more collateral than later redeemers, violating the principle of equal redemption rates.

## Description

In the `redeem_position` function, the redemption calculation uses the current `market_reserve_vault.amount` instead of `self.market.market_reserves`.

```rust
// Calculate proportional share of reserves
let reserves_to_redeem = (user_balance as u128)
    .checked_mul(self.market_reserve_vault.amount as u128)
    .ok_or(MintDecisionTokensError::MarketReservesOverflow)?
    .checked_div(total_supply as u128)
    .ok_or(MintDecisionTokensError::MarketReservesOverflow)? as u64;
```

**Vulnerability Details:**

1. **Dynamic Reserve Base**: The calculation uses `self.market_reserve_vault.amount` to calculate the value of reserves to redeem, which decreases after each redemption
2. **Unfair Distribution**: Earlier redeemers get higher redemption rates than later redeemers with identical positions
3. **Protocol Value Leakage**: Remaining collateral gets trapped in the protocol instead of being distributed to users

**Attack Scenario Example:**

**Initial State:**
- Market reserves: 1000 USDC
- YES token supply: 3000 tokens
- 3 users each hold 1000 YES tokens (should each get 333.33 USDC)

**Redemption Sequence:**
1. **User A redeems first:**
   - Calculation: `1000 × 1000 ÷ 3000 = 333.33 USDC` ✅ (correct)
   - Remaining reserves: 666.67 USDC

2. **User B redeems second:**
   - Calculation: `1000 × 666.67 ÷ 3000 = 222.22 USDC` ❌ (should be 333.33)
   - Remaining reserves: 444.45 USDC

3. **User C redeems third:**
   - Calculation: `1000 × 444.45 ÷ 3000 = 148.15 USDC` ❌ (should be 333.33)
   - Remaining reserves: 296.30 USDC

**Results:**
- User A: Gets 333.33 USDC ✅ (correct)
- User B: Gets 222.22 USDC ❌ (should be 333.33)
- User C: Gets 148.15 USDC ❌ (should be 333.33)
- Protocol: Keeps 296.30 USDC ❌ (should be 0)

## Recommendation

Fix the redemption calculation to use the original market reserves or maintain a fixed redemption rate:

**Option 1: Use Market.market_reserves (Fixed Base)**
```rust
// Calculate proportional share using fixed market reserves
let reserves_to_redeem = (user_balance as u128)
    .checked_mul(self.market.market_reserves as u128)
    .ok_or(MintDecisionTokensError::MarketReservesOverflow)?
    .checked_div(total_supply as u128)
    .ok_or(MintDecisionTokensError::MarketReservesOverflow)? as u64;
```
This fix ensures fair distribution where all users with equal positions receive equal redemption amounts, eliminating the first-come-first-serve advantage and preventing protocol value leakage.

# [H-03] : Double Fee Extraction and Excessive Market Reserve Allocation

## Summary
**Location**: `mint_decision_tokens.rs` lines 310-331

The protocol incorrectly transfers the full amount (including fees) to market reserves while also extracting fees separately, resulting in users paying approximately double the intended fees and markets receiving inflated reserves.

## Description

In the `mint_decision_tokens` function, there are two critical fee-related inconsistencies:

1. **Incorrect Market Reserve Transfer:**
```rust
// Transfer collateral from buyer to market vault
let transfer_ctx = CpiContext::new(
    self.token_program.to_account_info(),
    TransferChecked {
        from: self.buyer_collateral_token_account.to_account_info(),
        mint: self.collateral_token_mint.to_account_info(),
        to: self.market_reserve_vault.to_account_info(),
        authority: self.buyer.to_account_info(),
    }
);
//should have been amount_after_fee here
transfer_checked(transfer_ctx, amount, self.collateral_token_mint.decimals)?;
```

2. **Additional Fee Extraction:**
```rust
// Calculate fee amount
let fee_amount = amount.checked_sub(amount_after_fee)
    .ok_or(MintDecisionTokensError::ArithmeticError)?;

// Transfer 90% of fee to admin
let admin_fee = fee_amount.checked_mul(90)
    .and_then(|x| x.checked_div(100))
    .ok_or(MintDecisionTokensError::ArithmeticError)?;

transfer_checked(CpiContext::new(
    self.token_program.to_account_info(),
    TransferChecked {
        from: self.buyer_collateral_token_account.to_account_info(),
        mint: self.collateral_token_mint.to_account_info(),
        to: self.admin_collateral_token_account.to_account_info(),
        authority: self.buyer.to_account_info(),
    }
), admin_fee, self.collateral_token_mint.decimals)?;
// Transfer remaining 10% to market creator @audit 
let creator_fee = fee_amount.checked_sub(admin_fee)
    .ok_or(MintDecisionTokensError::ArithmeticError)?;
//@audit again taken from buyer
transfer_checked(CpiContext::new(
    self.token_program.to_account_info(), 
    TransferChecked {
        from: self.buyer_collateral_token_account.to_account_info(),
        mint: self.collateral_token_mint.to_account_info(),
        to: self.market_creator_collateral_token_account.to_account_info(),
        authority: self.buyer.to_account_info(),
    }
), creator_fee, self.collateral_token_mint.decimals)?;
```

**Vulnerability Details:**

1. **Double Fee Payment**: Users pay the full `amount` to market reserves AND pay separate fees to admin/creator
2. **Market Reserve Inflation**: Markets receive more collateral than they should, affecting token pricing via bonding curve
3. **Economic Imbalance**: Users pay ~6% fees instead of intended 3% (assuming 3% protocol fee)

**Attack/Impact Scenario:**

**Example with 100 USDC and 3% protocol fee:**

**Current (Buggy) Implementation:**
- User provides: 100 USDC
- Market receives: 100 USDC ❌ (should be 97 USDC)
- Admin receives: 2.7 USDC (90% of 3 USDC fee)
- Creator receives: 0.3 USDC (10% of 3 USDC fee)
- **Total extracted from user: 103 USDC** ❌
- **User overpays by: 6 USDC (6%)**

**Correct Implementation Should Be:**
- User provides: 100 USDC
- Market receives: 97 USDC ✅
- Admin receives: 2.7 USDC
- Creator receives: 0.3 USDC
- **Total extracted from user: 100 USDC** ✅

## Recommendation

Fix the market reserve transfer to use `amount_after_fee` instead of `amount`:

```rust
impl<'info> MintDecisionTokens<'info> {
    pub fn mint_decision_tokens(&mut self, amount: u64, buy_yes_token: bool, bumps: MintDecisionTokensBumps) -> Result<u64> {
        // ... existing validation code ...

        // Calculate amount after protocol fee
        let amount_after_fee = amount
            .checked_mul(10000_u64.checked_sub(self.global_config.fee).unwrap())
            .ok_or(MintDecisionTokensError::MarketReservesOverflow)?
            .checked_div(10000)
            .ok_or(MintDecisionTokensError::MarketReservesOverflow)?;

        // ... token minting code ...

        // Transfer ONLY amount_after_fee to market vault (FIX)
        let transfer_ctx = CpiContext::new(
            self.token_program.to_account_info(),
            TransferChecked {
                from: self.buyer_collateral_token_account.to_account_info(),
                mint: self.collateral_token_mint.to_account_info(),
                to: self.market_reserve_vault.to_account_info(),
                authority: self.buyer.to_account_info(),
            }
        );
        transfer_checked(transfer_ctx, amount_after_fee, self.collateral_token_mint.decimals)?;

        // Calculate fee amount
        let fee_amount = amount.checked_sub(amount_after_fee)
            .ok_or(MintDecisionTokensError::ArithmeticError)?;

        // Transfer fees to admin and creator (existing code is correct)
        // ... existing fee transfer code ...

        // Update market reserves with correct amount
        self.market.market_reserves = self.market.market_reserves
            .checked_add(amount_after_fee) // This is already correct
            .ok_or(MintDecisionTokensError::MarketReservesOverflow)?;

        // ... rest of function ...
    }
}
```

# [M-01] : Unnecessary Token Account Creation During Market Settlement

## Summary
**Location**: `mint_decision_tokens.rs` lines 146-164

The `settle_market` function unnecessarily creates associated token accounts for the admin when settling markets, leading to wasted gas and storage costs.

## Description

In the `MintDecisionTokens` account structure, the `buyer_yes_token_account` and `buyer_no_token_account` are defined with `init_if_needed` constraints:

```rust
/// Buyer's YES token account
#[account(
    init_if_needed,
    payer = buyer,
    associated_token::mint = yes_token_mint,
    associated_token::authority = buyer,
)]
pub buyer_yes_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

/// Buyer's NO token account
#[account(
    init_if_needed,
    payer = buyer,
    associated_token::mint = no_token_mint,
    associated_token::authority = buyer,
)]
pub buyer_no_token_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

When the admin calls `settle_market()`, the `buyer` field in the context refers to the admin account. This causes the system to automatically create associated token accounts for both YES and NO tokens for the admin, even though:

1. The admin doesn't need these token accounts for settlement operations
2. The admin will never receive or hold decision tokens during settlement
3. The `settle_market` function only updates market state and doesn't perform token transfers to the admin

This results in:
- Unnecessary rent costs (approximately 0.00203928 SOL per account × 2 accounts)
- Wasted transaction space and processing time
- Storage bloat on the blockchain

## Recommendation

Create a separate account structure specifically for market settlement operations that excludes the unnecessary token accounts:

```rust
#[derive(Accounts)]
pub struct SettleMarket<'info> {
    /// The admin's account, must be a signer
    #[account(mut)]
    pub admin: Signer<'info>,

    /// The prediction market account
    #[account(
        mut,
        seeds = [b"market".as_ref(), market.yes_token_mint.as_ref(), market.no_token_mint.as_ref()],
        bump = market.bump,
    )]
    pub market: Box<Account<'info, Market>>,

    /// Global configuration account
    #[account(
        seeds = [b"global_config".as_ref()],
        bump = global_config.bump,
        constraint = admin.key() == global_config.admin || admin.key() == global_config.oracle_program,
    )]
    pub global_config: Box<Account<'info, GlobalConfig>>,
}

// Then modify the settle_market function to use this new context
impl<'info> SettleMarket<'info> {
    pub fn settle_market(&mut self, yes_winner: bool) -> Result<WinningToken> {
        require!(!self.market.resolved, MintDecisionTokensError::MarketResolvedAlready);
        require!((self.market.end_time as i64) <= Clock::get()?.unix_timestamp, MintDecisionTokensError::MarketEnded);

        self.market.resolved = true;
        self.market.winning_token_id = if yes_winner {
            WinningToken::Yes
        } else {
            WinningToken::No
        };

        emit!(SettleMarketEvent {
            market: self.market.key(),
            yes_winner,
        });

        Ok(self.market.winning_token_id)
    }
}
```

This approach eliminates the unnecessary token account creation while maintaining all required functionality for market settlement.

# [M-02] : Market creators can farm rent sol

## Summary 
**Location**: `mint_decision_tokens.rs` lines 188-206

Market creators and admins can exploit the `init_if_needed` mechanism to farm rent SOL payments from users by repeatedly closing and recreating their associated token accounts across multiple instructions.

## Description

In the `MintDecisionTokens` account structure, the market creator and admin collateral token accounts are defined with `init_if_needed` and paid by the buyer:

```rust
/// Market creator's collateral token account
#[account(
    init_if_needed,
    payer = buyer,
    associated_token::mint = collateral_token_mint,
    associated_token::authority = market_creator,
)]
pub market_creator_collateral_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

/// Admin's collateral token account
#[account(
    init_if_needed,
    payer = buyer,
    associated_token::mint = collateral_token_mint,
    associated_token::authority = admin,
)]
pub admin_collateral_token_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**Vulnerability Details:**

1. **Rent Payment Exploitation**: The `payer = buyer` means users pay the rent for creating these accounts (~0.00203928 SOL each)
2. **Account Closure Attack**: Market creators and admins can close their token accounts to reclaim rent lamports
3. **Repeated Farming**: On subsequent transactions, the accounts are recreated with `init_if_needed`, and users pay rent again
4. **Multiple Attack Vectors**: This affects all four instructions that use the same account structure:
   - `mint_decision_tokens`
   - `burn_decision_tokens` 
   - `settle_market`
   - `redeem_position`

**Attack Scenario:**
1. User calls `mint_decision_tokens()` - pays rent to create market creator and admin token accounts
2. Market creator/admin closes their token accounts via `close_account` instruction - receives rent refund
3. Another user calls `burn_decision_tokens()` - pays rent again to recreate the accounts
4. Market creator/admin closes accounts again and repeats across all instructions
5. Process continues indefinitely across all four instruction types

**Realistic Attack Scenarios:**
  Consider a single polular marketa:
   - 500 transactions/day: ~2.04 SOL/day profit
   - Monthly: ~61.2 SOL (~$6,120 at $100/SOL)
   - Yearly: ~744 SOL (~$74,400)

## Recommendation

Modify the account structure to make the respective authorities pay for their own token account creation:

```rust
/// Market creator's collateral token account
#[account(
    init_if_needed,
    payer = market_creator,
    associated_token::mint = collateral_token_mint,
    associated_token::authority = market_creator,
)]
pub market_creator_collateral_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

/// Admin's collateral token account
#[account(
    init_if_needed,
    payer = admin,
    associated_token::mint = collateral_token_mint,
    associated_token::authority = admin,
)]
pub admin_collateral_token_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

# [M-03]: Missing Slippage Protection in Token Minting

## Summary  
**Location**: `mint_decision_tokens.rs` - mint_decision_tokens function

The `mint_decision_tokens` function lacks slippage protection, allowing users to receive fewer tokens than expected due to market changes between transaction submission and execution, particularly vulnerable to MEV attacks.

## Description

The current `mint_decision_tokens` function calculates token amounts based on real-time on-chain token supply without any slippage protection:

```rust
pub fn mint_decision_tokens(&mut self, amount: u64, buy_yes_token: bool, bumps: MintDecisionTokensBumps) -> Result<u64> {
    // ... validation code ...
    
    // Calculate tokens to mint using current on-chain supply
    let amount_to_mint = if buy_yes_token {
        PythagoreanBondingCurve::get_tokens_to_mint(
            self.market.market_reserves,
            self.yes_token_mint.supply,  // Uses dynamic on-chain supply
            self.no_token_mint.supply,   // Uses dynamic on-chain supply
            amount_after_fee
        )
    } else {
        PythagoreanBondingCurve::get_tokens_to_mint(
            self.market.market_reserves,
            self.no_token_mint.supply,   // Uses dynamic on-chain supply
            self.yes_token_mint.supply,  // Uses dynamic on-chain supply
            amount_after_fee
        )
    }.map_err(|_| error!(MintDecisionTokensError::TokenCalculationError))?;
    
    // Mint tokens without checking minimum expected amount
    // No slippage protection here
    Ok(amount_to_mint)
}
```

The function uses `self.yes_token_mint.supply` and `self.no_token_mint.supply` which reflect the current on-chain token supply that can change between transaction submission and execution. There is no mechanism for users to specify minimum acceptable token amounts.

## Recommendation

Implement slippage protection by adding a `min_tokens_out` parameter to ensure users receive minimum expected tokens:

```rust
pub fn mint_decision_tokens(
    &mut self, 
    amount: u64, 
    buy_yes_token: bool, 
    min_tokens_out: u64,  // NEW: Slippage protection parameter
    bumps: MintDecisionTokensBumps
) -> Result<u64> {
    // ... existing validation code ...
    
    // Calculate amount after protocol fee
    let amount_after_fee = amount
        .checked_mul(10000_u64.checked_sub(self.global_config.fee).unwrap())
        .ok_or(MintDecisionTokensError::MarketReservesOverflow)?
        .checked_div(10000)
        .ok_or(MintDecisionTokensError::MarketReservesOverflow)?;
    
    // Calculate tokens to mint using bonding curve
    let amount_to_mint = if buy_yes_token {
        PythagoreanBondingCurve::get_tokens_to_mint(
            self.market.market_reserves,
            self.yes_token_mint.supply,
            self.no_token_mint.supply,
            amount_after_fee
        )
    } else {
        PythagoreanBondingCurve::get_tokens_to_mint(
            self.market.market_reserves,
            self.no_token_mint.supply,
            self.yes_token_mint.supply,
            amount_after_fee
        )
    }.map_err(|_| error!(MintDecisionTokensError::TokenCalculationError))?;
    
    // SLIPPAGE PROTECTION: Check minimum tokens requirement
    require!(
        amount_to_mint >= min_tokens_out,
        MintDecisionTokensError::InsufficientTokensOut
    );
    
    // ... rest of minting logic ...
    
    Ok(amount_to_mint)
}
```

**Alternative Enhancement - Use Market State Instead of Mint Supply:**

Another improvement would be to use `self.market.yes_token_supply_minted` and `self.market.no_token_supply_minted` instead of `self.yes_token_mint.supply` for more predictable calculations:

```rust
let amount_to_mint = if buy_yes_token {
    PythagoreanBondingCurve::get_tokens_to_mint(
        self.market.market_reserves,
        self.market.yes_token_supply_minted,  // Use market state
        self.market.no_token_supply_minted,   // Use market state
        amount_after_fee
    )
} else {
    PythagoreanBondingCurve::get_tokens_to_mint(
        self.market.market_reserves,
        self.market.no_token_supply_minted,   // Use market state
        self.market.yes_token_supply_minted,  // Use market state
        amount_after_fee
    )
}
```

The slippage protection ensures users receive at least the minimum tokens they expect, preventing MEV exploitation and providing price certainty in volatile market conditions.

# [L-01] : Stale Getter Instructions Causing Denial of Service

**Location**: `lib.rs` lines 172-204

The getter instructions `get_market_end_time`, `get_yes_token_id`, and `get_no_token_id` use the `CreateMarket` context which contains `init` constraints, causing them to fail when called on existing markets.

## Description

The three getter functions incorrectly use the `CreateMarket` context:

```rust
/// Gets the end time of a market
pub fn get_market_end_time(ctx: Context<CreateMarket>) -> Result<u64> {
    Ok(ctx.accounts.market.end_time)
}

/// Gets the mint address of the YES token for a market
pub fn get_yes_token_id(ctx: Context<CreateMarket>) -> Result<Pubkey> {
    Ok(ctx.accounts.yes_token_mint.key())
}

/// Gets the mint address of the NO token for a market
pub fn get_no_token_id(ctx: Context<CreateMarket>) -> Result<Pubkey> {
    Ok(ctx.accounts.no_token_mint.key())
}
```

**Vulnerability Details:**

1. **Wrong Context Usage**: These functions use `CreateMarket` context which contains `init` constraints for mints and market accounts
2. **Initialization Conflict**: The `init` constraint attempts to create accounts that already exist for existing markets
3. **Denial of Service**: All calls to these getters fail with account already initialized errors
4. **Broken Functionality**: These functions become completely unusable after market creation

**Error Scenario:**
1. Market is created successfully using `create_market`
2. Client attempts to call `get_market_end_time` for the existing market
3. Anchor tries to initialize accounts that already exist due to `init` constraints
4. Transaction fails with "Account already initialized" error
5. Same failure occurs for `get_yes_token_id` and `get_no_token_id`

## Recommendation

Directly fetch those accounts on frontend via solana sdk.

# [L-02] : Missing Admin Transfer Functionality

## Summary
The protocol lacks functionality to transfer admin privileges.
## Description

The current protocol design stores the admin address in the `GlobalConfig` but provides no mechanism to change it:

```rust
pub struct GlobalConfig {
    pub admin: Pubkey,
    // ... other fields
}
```

The protocol has no way to change admin. Once set, the admin address cannot be changed, even if hacked. If admin loses keys, protocol becomes unmanageable forever. Cannot hand over admin rights in emergencies.

## Recommendation

Implement an admin transfer functionality with proper security measures:

```rust
#[derive(Accounts)]
pub struct TransferAdmin<'info> {
    /// Current admin account, must be a signer
    #[account(
        mut,
        constraint = current_admin.key() == global_config.admin @ TransferAdminError::Unauthorized,
    )]
    pub current_admin: Signer<'info>,

    /// New admin account
    /// CHECK: This will be the new admin
    pub new_admin: AccountInfo<'info>,

    /// Global configuration account
    #[account(
        mut,
        seeds = [b"global_config".as_ref()],
        bump = global_config.bump,
    )]
    pub global_config: Box<Account<'info, GlobalConfig>>,
}

impl<'info> TransferAdmin<'info> {
    pub fn transfer_admin(&mut self) -> Result<()> {
        require!(
            self.new_admin.key() != self.current_admin.key(),
            TransferAdminError::SameAdmin
        );

        let old_admin = self.global_config.admin;
        self.global_config.admin = self.new_admin.key();

        emit!(AdminTransferEvent {
            old_admin,
            new_admin: self.new_admin.key(),
        });

        Ok(())
    }
}

#[event]
pub struct AdminTransferEvent {
    pub old_admin: Pubkey,
    pub new_admin: Pubkey,
}

#[error_code]
pub enum TransferAdminError {
    #[msg("Unauthorized: Only current admin can transfer admin rights")]
    Unauthorized,
    
    #[msg("Cannot transfer admin to the same account")]
    SameAdmin,
}
```

**Even better would be a Two-Step Transfer:**

```rust
pub struct GlobalConfig {
    pub admin: Pubkey,
    pub pending_admin: Option<Pubkey>,
    // ... other fields
}

// Step 1: Current admin proposes new admin
pub fn propose_admin_transfer(&mut self, new_admin: Pubkey) -> Result<()> {
    self.global_config.pending_admin = Some(new_admin);
    // Emit event
    Ok(())
}

// Step 2: New admin accepts the transfer
pub fn accept_admin_transfer(&mut self) -> Result<()> {
    require!(
        Some(self.new_admin.key()) == self.global_config.pending_admin,
        TransferAdminError::NotPendingAdmin
    );
    
    self.global_config.admin = self.new_admin.key();
    self.global_config.pending_admin = None;
    // Emit event
    Ok(())
}
```

# [L-03] : Missing Protocol Pause Functionality

## Summary 
**Location**: Global Protocol Design

The protocol lacks pause functionality, preventing emergency stops during critical vulnerabilities, exploits, or maintenance periods.

## Description

The current protocol has no mechanism to pause operations during emergencies or maintenance:

```rust
pub struct GlobalConfig {
    pub admin: Pubkey,
    pub fee: u64,
    // Missing: pub paused: bool,
    // ... other fields
}
```

## Recommendation

Implement comprehensive pause functionality