# Awesome Solana Security Checklist

A curated collection of resources and best practices for Solana program security by [Arjuna](x.com/arjuna_sec). 

For audits reach out at : [here](https://t.me/calc1f4r)

## Table of Contents
- [Account Validations](#account-validations)
  - [Signer Checks](#signer-checks)
  - [Writer Checks](#writer-checks)
  - [Owner Checks](#owner-checks)
  - [PDA Validation](#pda-validation)
- [Account Data Reallocation](#account-data-reallocation)
- [Lamports Transfer Out of PDA](#lamports-transfer-out-of-pda)
- [CPI Issues](#cpi-issues)
- [Unvalidated account](#unvalidated-account)
  - [Token Program Check](#token-program-check)
  - [Sysvar Account Check](#sysvar-account-check)
  - [Token Account Ownership Check](#token-account-ownership-check)
  - [Token Account Existence Check](#token-account-existence-check)
  - [Remaining Accounts](#remaining-accounts)
- [Account Reloading](#account-reloading)
- [DOS vectors](#dos-vectors)
  - [Associated Token Account Initialization](#associated-token-account-initialization)
  - [Account Pre-creation Attack](#account-pre-creation-attack)
- [Mint Issues](#mint-issues)
  - [Missing check for mint close authority extension](#missing-check-for-mint-close-authority-extension)
  - [Missing check for mint freeze authority](#missing-check-for-mint-freeze-authority)
  - [Fee on transfer extension not properly handled](#fee-on-transfer-extension-not-properly-handled)
- [Event emission issues](#event-emission-issues)
  - [Wrong event emission](#wrong-event-emission)
  - [Missing event emission on critical state updates](#missing-event-emission-on-critical-state-updates)
- [Arithmetic and Data Handling Security](#arithmetic-and-data-handling-security)
  - [Integer Overflow/Underflow Protection](#integer-overflowunderflow-protection)
  - [Division Safety](#division-safety)
  - [Precision Loss Prevention](#precision-loss-prevention)
  - [Safe Type Casting](#safe-type-casting)
  - [Rounding Considerations](#rounding-considerations)
  - [Error Handling](#error-handling)
  - [Decimal Handling](#decimal-handling)
- [Resources](#resources)
  - [Official Documentation](#official-documentation)
  - [Security Best Practices](#security-best-practices)
- [Seed Collisions](#seed-collisions)
  - [The Vulnerability](#the-vulnerability)
  - [Example Scenario](#example-scenario)
  - [Recommended Mitigation](#recommended-mitigation)


## Account Validations

### Signer Checks
- Missing signer check
```rust
// ❌ Bad
let account = ctx.accounts.account;

// ✅ Good - Native
require!(account.is_signer, ErrorCode::MissingSigner);

// ✅ Good - Anchor
#[account(
    constraint = account.is_signer @ ErrorCode::MissingSigner
)]
pub account: Account<AccountType>,

// GOOD - Anchor 
 pub creator: Signer<'info>,
#[]
```
Impact: Without signer validation, any account can be used in place of the intended signer, potentially allowing unauthorized access to program functions.

### Writer Checks
- Missing writer check
```rust
// ❌ Bad
let account = ctx.accounts.account;

// ✅ Good - Native
require!(account.is_writable, ErrorCode::AccountNotWritable);

// ✅ Good - Anchor
#[account(
    mut,
    constraint = account.is_writable @ ErrorCode::AccountNotWritable
)]
pub account: Account<AccountType>,

// ✅ Good - Anchor 
    #[account(mut)]
    pub creator: AccountInfo<'info>,
```
Impact: Attempting to modify a non-writable account will cause transaction failure. Always verify account mutability before attempting modifications.

### Owner Checks
- Missing owner check
```rust
// ❌ Bad
let account = ctx.accounts.account;

// ✅ Good - Native
require!(account.owner == program_id, ErrorCode::InvalidOwner);

// ✅ Good - Anchor explictiy
#[account(
    constraint = account.owner == program_id @ ErrorCode::InvalidOwner
)]
pub account: Account<AccountType>,


// Good - Anchor : if you use systemprogram accounts or pda derived using the same program use the anchor type
pub pool: <Account<'info, Pool>>, // pool will be validated to be owned by the our program id 

pub token_2022_program: Program<'info, Token2022>, // system owned accounts will be validated by anchor on its own

```
Impact: Without owner validation, malicious accounts owned by other programs could be used, potentially leading to unauthorized state modifications or data theft.

### PDA Validation
- Missing PDA validation
```rust
// ❌ Bad
let pda = ctx.accounts.pda;

// ✅ Good - Native
let (expected_pda, _bump) = Pubkey::find_program_address(
    &[b"prefix", other_seed],
    program_id
);
require!(pda.key() == expected_pda, ErrorCode::InvalidPDA);

// ✅ Good - Anchor
#[account(
    seeds = [b"prefix", other_seed],
    bump,
    constraint = pda.key() == Pubkey::find_program_address(
        &[b"prefix", other_seed],
        program_id
    ).0 @ ErrorCode::InvalidPDA
)]
pub pda: Account<PdaAccount>,
```
Impact: Invalid PDAs could be used to access or modify data meant for specific program-derived addresses, potentially compromising program security.

## Account Data Reallocation
- Unsafe reallocation without proper memory management
```rust
// ❌ Bad
// Directly reallocating without proper memory handling
account.realloc(new_size, false)?;

// ❌ Bad
// Reallocating without zero-initialization
let current_data_size = account.data.borrow().len();
if current_data_size < new_size {
    account.realloc(new_size, false)?;
}

// ✅ Good
// Safely reallocating with proper memory management
let current_data_size = account.data.borrow().len();
account.realloc(new_size, false)?;
if current_data_size < new_size {
    // Zero-initialize the new memory region
    let data = &mut account.data.borrow_mut();
    for i in current_data_size..new_size {
        data[i] = 0;
    }
}
```
Impact: Improper memory management during reallocation can lead to memory corruption, uninitialized memory access, or exploitation of sensitive data left in uninitialized memory regions. This can result in security vulnerabilities including potential account takeovers or data leakage.

- Not handling memory allocation failures
```rust
// ❌ Bad
// No error handling for reallocation failures
account.realloc(new_size, false);

// ✅ Good
// Proper error handling for reallocation
account.realloc(new_size, false)
    .map_err(|_| ProgramError::AccountDataTooSmall)?;
```
Impact: Failing to handle memory allocation errors can lead to unexpected program behavior, potential vulnerabilities, and denial of service attacks.

## Lamports Transfer Out of PDA
- Missing rent exempt after transfer check
```rust
// ❌ Bad
let pda = ctx.accounts.pda;
pda.try_borrow_mut_lamports()? -= amount;

// ✅ Good -
let pda = ctx.accounts.pda;
let rent = Rent::get()?;
let min_rent = rent.minimum_balance(pda.data_len());
let current_lamports = pda.lamports();
require!(
    current_lamports - amount >= min_rent,
    ErrorCode::InsufficientFundsForRent
);
pda.try_borrow_mut_lamports()? -= amount;

```
Impact: The PDA will be garbage collected if it falls below the minimum rent-exempt balance, potentially causing data loss and program state inconsistencies.

- Using signer seeds instead of try borrow lamports
```rust
// ❌ Bad
let pda = ctx.accounts.pda;
let seeds = &[b"prefix", other_seed];
let signer = &[&seeds[..], &[bump]];
system_program::transfer(
    CpiContext::new_with_signer(
        ctx.accounts.system_program.to_account_info(),
        system_program::Transfer {
            from: pda.to_account_info(),
            to: recipient.to_account_info(),
        },
        signer,
    ),
    amount,
)?;

// ✅ Good - Native
let pda = ctx.accounts.pda;
pda.try_borrow_mut_lamports()? -= amount;
recipient.try_borrow_mut_lamports()? += amount;
```
Impact: Using signer seeds for transfers from a pda won't succeed, as only system program can only deduct balances.

Reference : https://solanacookbook.com/references/programs.html#how-to-transfer-sol-in-a-program

## CPI Issues 

- Right order of CPI accounts not validated 
```rust
// ❌ Vulnerable: Incorrect account ordering in CPI call.
// The accounts are passed in an order that does not match the expected order of the callee.
let accounts = vec![
    // WRONG: 'account2' is placed first instead of 'account1'
    ctx.accounts.account2.to_account_info(),
    ctx.accounts.account1.to_account_info(),
];
let cpi_accounts = accounts.as_slice();

other_program::cpi::some_instruction(
    CpiContext::new(
        ctx.accounts.other_program.to_account_info(),
        other_program::cpi::SomeInstruction { accounts: cpi_accounts },
    ),
)?;

// 🟢 Correct way

other_program::cpi::some_instruction(
    CpiContext::new(
        ctx.accounts.other_program.to_account_info(),
        other_program::cpi::SomeInstruction {
            account1: ctx.accounts.account1.to_account_info(),
            account2: ctx.accounts.account2.to_account_info(),
        },
    ),
)?;


```
Impact: Incorrect account ordering in CPI calls can lead to unexpected behavior, mainly tx failures.

- Missing bump value in signer seeds
```rust
// ❌ Bad - Missing bump value in signer seeds
let seeds = &[b"prefix", other_seed];
let signer = &[&seeds[..]]; // Missing bump value
system_program::transfer(
    CpiContext::new_with_signer(
        ctx.accounts.system_program.to_account_info(),
        system_program::Transfer {
            from: pda.to_account_info(),
            to: recipient.to_account_info(),
        },
        signer,
    ),
    amount,
)?;

// ✅ Good - Include bump value in signer seeds
let (pda, bump) = Pubkey::find_program_address(
    &[b"prefix", other_seed],
    program_id
);
let seeds = &[b"prefix", other_seed];
let signer = &[&seeds[..], &[bump]];
system_program::transfer(
    CpiContext::new_with_signer(
        ctx.accounts.system_program.to_account_info(),
        system_program::Transfer {
            from: pda.to_account_info(),
            to: recipient.to_account_info(),
        },
        signer,
    ),
    amount,
)?;
```
Impact: Without including the bump value in signer seeds, the PDA signature verification will fail, causing the transaction to revert.

- Incorrect or missing seeds in signer seeds
```rust
// ❌ Bad - Missing required seed
let seeds = &[b"prefix"]; // Missing other_seed
let signer = &[&seeds[..], &[bump]];

// ❌ Bad - Incorrect seed order
let seeds = &[other_seed, b"prefix"]; // Wrong order
let signer = &[&seeds[..], &[bump]];

// ✅ Good - Correct seeds in proper order
let (pda, bump) = Pubkey::find_program_address(
    &[b"prefix", other_seed],
    program_id
);
let seeds = &[b"prefix", other_seed];
let signer = &[&seeds[..], &[bump]];
```
Impact: Incorrect or missing seeds in signer seeds will cause PDA signature verification to fail, potentially causing  transaction failures.

- Arbitrary CPI
```rust
// ❌ Bad
let arbitrary_program = ctx.accounts.arbitrary_program;
let arbitrary_accounts = ctx.accounts.arbitrary_accounts;
arbitrary_program::cpi::arbitrary_instruction(
    CpiContext::new(
        arbitrary_program.to_account_info(),
        arbitrary_program::cpi::ArbitraryInstruction {
            accounts: arbitrary_accounts,
        },
    ),
)?;

// ✅ Good - Native
let known_program = ctx.accounts.known_program;
require!(
    known_program.key() == KNOWN_PROGRAM_ID,
    ErrorCode::InvalidProgram
);
known_program::cpi::safe_instruction(
    CpiContext::new(
        known_program.to_account_info(),
        known_program::cpi::SafeInstruction {
            accounts: ctx.accounts.safe_accounts,
        },
    ),
)?;

// ✅ Good - Anchor
#[account(
    constraint = known_program.key() == KNOWN_PROGRAM_ID @ ErrorCode::InvalidProgram
)]
pub known_program: Program<'info, KnownProgram>,
```
Impact: Allowing arbitrary CPI calls can enable malicious programs to execute unauthorized operations or manipulate program state through untrusted external calls.

## Unvalidated account

- Missing check for rent account to be the same
```rust
// ❌ Bad
let rent = ctx.accounts.rent;

// ✅ Good - Native
require!(
    ctx.accounts.rent.key() == sysvar::rent::ID,
    ErrorCode::InvalidRentAccount
);

// ✅ Good - Anchor
#[account(
    constraint = rent.key() == sysvar::rent::ID @ ErrorCode::InvalidRentAccount
)]
pub rent: Sysvar<'info, Rent>,
```
Impact: Using an incorrect rent account could lead to incorrect rent calculations and potential security vulnerabilities.

### Token Program Check
- Missing check for token program
```rust
// ❌ Bad
let token_program = ctx.accounts.token_program;

// ✅ Good - Native
require!(
    ctx.accounts.token_program.key() == spl_token::ID,
    ErrorCode::InvalidTokenProgram
);

// ✅ Good - Anchor
#[account(
    constraint = token_program.key() == spl_token::ID @ ErrorCode::InvalidTokenProgram
)]
pub token_program: Program<'info, Token>,
```
Impact: Without validating the token program, malicious token programs could be used to manipulate token operations.

### Sysvar Account Check
- Missing check for Sysvar account

These are the actual system program accounts 
```markdown
Clock: SysvarC1ock11111111111111111111111111111111
EpochSchedule: SysvarEpochSchedu1e111111111111111111111111
Fees: SysvarFees111111111111111111111111111111111
Instructions: Sysvar1nstructions111111111111111111111111111
RecentBlockhashes: SysvarRecentB1ockHashes11111111111111111111
Rent: SysvarRent111111111111111111111111111111111
SlotHashes: SysvarS1otHashes111111111111111111111111111
SlotHistory: SysvarS1otHistory11111111111111111111111111
StakeHistory: SysvarStakeHistory1111111111111111111111111
SPL token program: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
```
```rust
// ❌ Bad
let sysvar = ctx.accounts.sysvar;

// ✅ Good - Native
require!(
    ctx.accounts.sysvar.key() == sysvar::rent::ID || 
    ctx.accounts.sysvar.key() == sysvar::clock::ID ||
    ctx.accounts.sysvar.key() == sysvar::slot_hashes::ID,
    ErrorCode::InvalidSysvarAccount
);

// ✅ Good - Anchor
pub sysvar: Sysvar<'info, Rent>,
```
Impact: Incorrect sysvar accounts could lead to incorrect program behavior and potential security issues.

### Token Account Ownership Check
- Missing check for Token Account Ownership
```rust
// ❌ Bad
let token_account = ctx.accounts.token_account;

// ✅ Good - Native
require!(
    token_account.owner == expected_owner,
    ErrorCode::InvalidTokenAccountOwner
);

// ✅ Good - Anchor
#[account(
    constraint = token_account.owner == expected_owner @ ErrorCode::InvalidTokenAccountOwner
)]
pub token_account: Account<TokenAccount>,

// ✅ good - Anchor 
#[account(token::authority = authority)]
pub token_account: Account<'info, TokenAccount>,
```
Impact: Without validating token account ownership, tokens could be stolen or manipulated by unauthorized users.



### Remaining Accounts
- Missing validation on accounts in the `remaining_accounts` field
```rust
// ❌ Bad: No validation of remaining_accounts
fn process_instruction(ctx: Context<Instruction>) -> Result<()> {
    // Accessing accounts from remaining_accounts without validation
    let accounts = ctx.remaining_accounts;
    for account in accounts {
        // Operating on the account without validation
        // ...
    }
    Ok(())
}

// ✅ Good: Validate each account in remaining_accounts
fn process_instruction(ctx: Context<Instruction>) -> Result<()> {
    let accounts = ctx.remaining_accounts;
    for account in accounts {
        // Validate account owner
        require!(
            account.owner == &TOKEN_PROGRAM_ID || 
            account.owner == &program_id(),
            ErrorCode::InvalidAccountOwner
        );
        
        // Additional validation based on expected account types
        // ...
    }
    Ok(())
}
```
Impact: Without validating accounts passed through `remaining_accounts`, attackers can pass in malicious or unexpected accounts, potentially leading to unauthorized access, fund theft, or manipulation of program state. validate them according to your needs 

## Account Reloading
- Not refreshing accounts after modifications through CPI calls
```rust
// ❌ Bad: Account state not refreshed after CPI
fn process_token_transfer(ctx: Context<TransferTokens>) -> Result<()> {
    // Perform a CPI that modifies the 'source_token' account
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.source_token.to_account_info(),
                to: ctx.accounts.destination_token.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        ),
        amount,
    )?;
    
    // Incorrect: Using the same account state that was loaded at transaction start
    // The account.amount no longer reflects the actual on-chain state
    let remaining_balance = ctx.accounts.source_token.amount;
    
    // ... logic dependent on remaining_balance ...
}

// ✅ Good: Refresh account state after CPI
fn process_token_transfer(ctx: Context<TransferTokens>) -> Result<()> {
    // Perform a CPI that modifies the 'source_token' account
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.source_token.to_account_info(),
                to: ctx.accounts.destination_token.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        ),
        amount,
    )?;
    
    // Correct: Reload account data from storage
    ctx.accounts.source_token.reload()?;
    
    // Now we have the current on-chain state
    let remaining_balance = ctx.accounts.source_token.amount;
    
    // ... logic dependent on remaining_balance ...
}
```
Impact: Solana loads accounts only once at the beginning of a transaction. When an account's state changes through a CPI call, the program's view of that account becomes outdated. Using outdated account state can lead to incorrect calculations, logic errors, and potential security vulnerabilities.

## DOS vectors 

### Associated Token Account Initialization
- Using `init` instead of `init_if_needed` for ATA creation
```rust
// ❌ Bad - Using init for ATA creation
#[account(
    init,
    payer = user,
    associated_token::mint = mint,
    associated_token::authority = user,
)]
pub token_account: Account<'info, TokenAccount>,

// ✅ Good - Using init_if_needed for ATA creation
#[account(
    init_if_needed,
    payer = user,
    associated_token::mint = mint,
    associated_token::authority = user,
)]
pub token_account: Account<'info, TokenAccount>,
```
Impact: Using `init` instead of `init_if_needed` for ATA creation will cause transactions to fail if the token account already exists, enabling attackers to front-run legitimate transactions by creating accounts first, resulting in denial of service.

### Account Pre-creation Attack
- Not handling cases where accounts could be pre-created by attackers
```rust
// ❌ Bad - Vulnerable to pre-creation attacks
#[account(
    init,
    payer = user,
    space = 8 + size,
    seeds = [b"account", user.key().as_ref()],
    bump
)]
pub data_account: Account<'info, DataAccount>,

// ✅ Good - Using init_if_needed to handle pre-created accounts
#[account(
    init_if_needed,
    payer = user,
    space = 8 + size,
    seeds = [b"account", user.key().as_ref()],
    bump
)]
pub data_account: Account<'info, DataAccount>,

// ✅ Good - Additional validation for pre-existing accounts
#[account(
    init_if_needed,
    payer = user,
    space = 8 + size,
    seeds = [b"account", user.key().as_ref()],
    bump,
    constraint = data_account.owner == program_id @ ErrorCode::InvalidOwner
)]
pub data_account: Account<'info, DataAccount>,
```
Impact: When a program expects to create an account but doesn't handle pre-existing accounts, attackers can front-run transactions and create the targeted accounts first, causing legitimate transactions to fail and creating denial of service conditions.

Reference : https://code4rena.com/reports/2025-01-pump-science#h-01-the-lock_pool-operation-can-be-dos


### Account Existence Check
- Using lamports to check if a  account exists
```rust
// ❌ Bad: Checking token account existence with lamports
if token_account.lamports() > 0 {
    // Token account exists
    // Proceed with operations
}

// ❌ Bad: Using rent-exemption as existence check
let rent = Rent::get()?;
if token_account.lamports() >= rent.minimum_balance(TokenAccount::LEN) {
    // Token account exists
    // Proceed with operations
}

// ✅ Good: Properly validate token account existence and data
// Check if the account exists and contains valid token data
if !token_account.data_is_empty() && token_account.owner == &spl_token::ID {
    let token_data = TokenAccount::try_deserialize(&mut &token_account.data.borrow()[..])?;
    // Now we can safely use the token data
}

// ✅ Good: Use Anchor's Account type which validates existence and ownership
#[account(
    constraint = token_account.mint == expected_mint @ ErrorCode::InvalidMint,
)]
pub token_account: Account<'info, TokenAccount>,
```
Impact: Relying on lamports to verify  account existence is vulnerable to donation attacks, where an attacker can transfer lamports to an uninitialized account to make it appear valid. This can lead to operations on invalid accounts, which may cause unexpected behavior, data corruption, or theft of tokens.
### Mint Issues

- Missing check for mint close authority extension
```rust
// ❌ Bad: No validation of close authority
let mint = ctx.accounts.mint;

// ✅ Good: Validate close authority is not set or expected
let mint = ctx.accounts.mint;
let close_authority = spl_token_2022::extension::close_authority::get_close_authority(&mint.to_account_info())?;
require!(close_authority.is_none(), ErrorCode::UnexpectedCloseAuthority);
```
Impact: If close authority is set, the mint could be closed by the authority, potentially rendering tokens worthless.

- Missing check for mint freeze authority
```rust
// ❌ Bad: No validation of freeze authority
let mint = ctx.accounts.mint;

// ✅ Good: Validate freeze authority is not set or expected
let mint = ctx.accounts.mint;
require!(mint.freeze_authority.is_none(), ErrorCode::UnexpectedFreezeAuthority);
```
Impact: If freeze authority is set, user token accounts could be frozen, preventing users from transferring their tokens, raydium does not allow mint with freeze authority 


- Fee on transfer extension not properly handled
```rust
// ❌ Bad: Using basic transfer with fee-enabled token
token::transfer(
    ctx.accounts.token_program.to_account_info(),
    ctx.accounts.from.to_account_info(),
    ctx.accounts.to.to_account_info(),
    ctx.accounts.authority.to_account_info(),
    &[],
    amount,
)?;

// ✅ Good: Using transfer_checked for fee-enabled tokens
token::transfer_checked(
    ctx.accounts.token_program.to_account_info(),
    ctx.accounts.from.to_account_info(),
    ctx.accounts.mint.to_account_info(),
    ctx.accounts.to.to_account_info(),
    ctx.accounts.authority.to_account_info(),
    &[],
    amount,
    mint.decimals,
)?;
```
Impact: Using `transfer` instead of `transfer_checked` with fee-enabled tokens can lead to unexpected token amounts being received, potentially causing accounting errors. 

Reference : https://spl.solana.com/token-2022/extensions#transfer-fees


## Event emission issues

### Wrong event emission
- Emitting incorrect or misleading event data
```rust
// ❌ Bad: Emitting incorrect event data
fn transfer_tokens(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    // Perform transfer logic...
    
    // Incorrect: Emitting wrong amount in event
    msg!("Transfer completed: amount={}", amount + fee);  // Wrong: includes fee in reported amount
    emit!(TransferEvent {
        from: ctx.accounts.sender.key(),
        to: ctx.accounts.receiver.key(),
        amount: amount + fee,  // Wrong: includes fee in reported amount
    });
    
    Ok(())
}

// ✅ Good: Emitting accurate event data
fn transfer_tokens(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    // Perform transfer logic...
    
    // Correct: Emitting accurate information
    msg!("Transfer completed: amount={}, fee={}", amount, fee);
    emit!(TransferEvent {
        from: ctx.accounts.sender.key(),
        to: ctx.accounts.receiver.key(),
        amount: amount,
        fee: fee,
    });
    
    Ok(())
}
```
Impact: Incorrect event data can mislead users and off-chain systems, causing accounting errors and confusion. This may also affect indexers and dashboards that rely on event data.

### Missing event emission on critical state updates
- Failing to emit events for important state changes
```rust
// ❌ Bad: Missing event for critical state change
fn update_admin(ctx: Context<UpdateAdmin>) -> Result<()> {
    let program_state = &mut ctx.accounts.program_state;
    
    // Critical state change without event
    program_state.admin = ctx.accounts.new_admin.key();
    
    Ok(())
}

// ✅ Good: Including events for all critical state changes
fn update_admin(ctx: Context<UpdateAdmin>) -> Result<()> {
    let program_state = &mut ctx.accounts.program_state;
    
    // Store old admin for event
    let old_admin = program_state.admin;
    
    // Update state
    program_state.admin = ctx.accounts.new_admin.key();
    
    // Emit event for the critical change
    msg!("Admin changed from {} to {}", 
        old_admin, ctx.accounts.new_admin.key());
    emit!(AdminChangedEvent {
        old_admin: old_admin,
        new_admin: ctx.accounts.new_admin.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });
    
    Ok(())
}
```
Impact: Missing events for critical state changes makes it difficult to track important program updates, audit program activity, and notify users of significant changes. This reduces transparency and can hamper off-chain monitoring systems from detecting potentially malicious activities.

## Arithmetic and Data Handling Security

### Integer Overflow/Underflow Protection
- Missing checks for arithmetic operations
```rust
// ❌ Bad: Unchecked arithmetic
let balance = account.balance + amount;

// ✅ Good: Checked arithmetic
let balance = account.balance.checked_add(amount)
    .ok_or(ProgramError::Overflow)?;
```
Impact: Unchecked arithmetic operations can lead to integer overflow or underflow, resulting in incorrect calculations and potential loss of funds.

### Division Safety
- Missing checks for zero divisors
```rust
// ❌ Bad: Unchecked division
let result = total / divisor;

// ✅ Good: Check for zero before division
if divisor == 0 {
    return Err(ProgramError::InvalidArgument);
}
let result = total / divisor;
```
Impact: Division by zero can cause program crashes and transaction failures.

### Precision Loss Prevention
- Missing consideration for precision in calculations
```rust
// ❌ Bad: Potential precision loss
let rate = (amount * 100) / total;

// ✅ Good: Maintain precision
let rate = amount.checked_mul(100)
    .ok_or(ProgramError::Overflow)?
    .checked_div(total)
    .ok_or(ProgramError::Overflow)?;
```
Impact: Loss of precision in financial calculations can lead to incorrect values and potential fund discrepancies.

### Safe Type Casting
- Unchecked type conversions
```rust
// ❌ Bad: Unsafe casting
let small_num = big_num as u64;

// ✅ Good: Safe casting with checks
let small_num = u64::try_from(big_num)
    .map_err(|_| ProgramError::InvalidArgument)?;
```
Impact: Unchecked type conversions can lead to data corruption or unexpected behavior.

### Rounding Considerations
- Implicit rounding behavior
```rust
// ❌ Bad: Implicit rounding
let shares = total_shares * amount / total_supply;

// ✅ Good: Explicit rounding with checks
let shares = total_shares
    .checked_mul(amount)?
    .checked_add(total_supply.checked_sub(1)?)?
    .checked_div(total_supply)?;  // Ceiling division
```
Impact: Incorrect rounding behavior can affect calculations, especially in financial operations.

### Error Handling
- Missing error handling for arithmetic operations
```rust
// ❌ Bad: No error handling
fn calculate_amount(base: u64, multiplier: u64) -> u64 {
    base * multiplier
}

// ✅ Good: Proper error handling
fn calculate_amount(base: u64, multiplier: u64) -> Result<u64, ProgramError> {
    base.checked_mul(multiplier)
        .ok_or(ProgramError::Overflow)
}
```
Impact: Insufficient handling of arithmetic errors can lead to unhandled exceptions and potential vulnerabilities.

### Decimal Handling
- Improper handling of decimal calculations
```rust
// ❌ Bad: Direct decimal operations
let price = raw_price / 100;  // For 2 decimal places

// ✅ Good: Using decimal handling library
use anchor_decimal::Decimal;

let price = Decimal::from_price(raw_price, 2)?;
```
Impact: Improper handling of decimal calculations can lead to rounding errors and incorrect financial calculations.

## Resources

### Official Documentation
- [Solana Program Security Course](https://solana.com/developers/courses/program-security)

### Security Best Practices
- [Token-2022 Security Best Practices](https://blog.offside.io/p/token-2022-security-best-practices-part-1)
- [Common Vulnerabilities in Anchor Programs](https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/)
- [A Hitchhiker's Guide to Solana Program Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- [Token-2022 Security Best Practices Part 2](https://blog.offside.io/p/token-2022-security-best-practices-part-2)
- [Solana Program Security Research](https://research.kudelskisecurity.com/2021/09/15/solana-program-security-part1/)
- [Solana Smart Contract Security Best Practices](https://github.com/slowmist/solana-smart-contract-security-best-practices)

## Seed Collisions

### The Vulnerability
Seed collisions occur when two different sets of seed values generate the same Program Derived Address (PDA). This vulnerability can lead to account confusion, where one account is mistaken for another, potentially resulting in denial of service attacks or complete compromise of program functionality.

### Example Scenario
```rust
// ❌ Bad - Using simple seeds that might collide
#[account(
    init,
    payer = user,
    space = 8 + size,
    seeds = [b"vote", session_id.as_bytes()],
    bump
)]
pub vote_account: Account<'info, VoteAccount>,

// Another part of the program that could generate the same PDA
#[account(
    init,
    payer = organizer,
    space = 8 + size,
    seeds = [b"vote", different_id.as_bytes()],
    bump
)]
pub session_account: Account<'info, SessionAccount>,
```

### Recommended Mitigation
```rust
// ✅ Good - Using unique prefixes and additional context in seeds
#[account(
    init,
    payer = user,
    space = 8 + size,
    seeds = [b"vote_session", organizer.key().as_ref(), session_id.as_bytes()],
    bump
)]
pub vote_account: Account<'info, VoteAccount>,

// Different purpose uses different prefix
#[account(
    init,
    payer = voter,
    space = 8 + size,
    seeds = [b"user_vote", session_id.as_bytes(), voter.key().as_ref()],
    bump
)]
pub user_vote: Account<'info, UserVote>,
```

To mitigate seed collision vulnerabilities:

1. Use unique prefixes for seeds across different PDAs in the same program
2. Include additional contextual data in seeds (e.g., user public keys, timestamps)
3. When using user-supplied data as seeds, validate its uniqueness or add program-controlled components
4. Consider using a nonce value as part of the seed to ensure uniqueness
5. Test your program with various seed inputs to verify no collisions occur in expected usage patterns

Impact: Seed collisions can lead to account confusion, where a PDA created for one purpose is mistakenly used for another. This can result in security vulnerabilities including denial of service, account takeovers, or data corruption.