# Awesome Solana Security Checklist

A curated collection of resources and best practices for Solana program security by [Arjuna](x.com/arjuna_sec). 

## Account Validations

### Signer Checks
- [ ] Missing signer check
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
- [ ] Missing writer check
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
- [ ] Missing owner check
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
- [ ] Missing PDA validation
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

## Lamports Transfer Out of PDA
- [ ] Missing rent exempt after transfer check
```rust
// ❌ Bad
let pda = ctx.accounts.pda;
pda.try_borrow_mut_lamports()? -= amount;

// ✅ Good - Native
let pda = ctx.accounts.pda;
let rent = Rent::get()?;
let min_rent = rent.minimum_balance(pda.data_len());
let current_lamports = pda.lamports();
require!(
    current_lamports - amount >= min_rent,
    ErrorCode::InsufficientFundsForRent
);
pda.try_borrow_mut_lamports()? -= amount;

// ✅ Good - Anchor
#[account(
    constraint = {
        let rent = Rent::get()?;
        let min_rent = rent.minimum_balance(pda.data_len());
        pda.lamports() - amount >= min_rent
    } @ ErrorCode::InsufficientFundsForRent
)]
pub pda: Account<'info, PdaAccount>,
```
Impact: The PDA will be garbage collected if it falls below the minimum rent-exempt balance, potentially causing data loss and program state inconsistencies.

- [ ] Using signer seeds instead of try borrow lamports
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

// ✅ Good - Anchor
#[account(mut)]
pub pda: Account<'info, PdaAccount>,
#[account(mut)]
pub recipient: Account<'info, SystemAccount>,
```
Impact: Using signer seeds for transfers can lead to transaction failures and potential race conditions. Direct lamport manipulation is more efficient and safer.

### CPI Issues 

- [ ] Right order of CPI accounts not validated 
```rust
// ❌ Bad - Arbitrary account ordering can lead to security vulnerabilities
let accounts = vec![
    ctx.accounts.account1.to_account_info(),
    ctx.accounts.account2.to_account_info(),
];
let cpi_accounts = accounts.as_slice();
other_program::cpi::some_instruction(
    CpiContext::new(
        ctx.accounts.other_program.to_account_info(),
        other_program::cpi::SomeInstruction { accounts: cpi_accounts },
    ),
)?;

// ✅ Good - Native
other_program::cpi::some_instruction(
    CpiContext::new(
        ctx.accounts.other_program.to_account_info(),
        other_program::cpi::SomeInstruction {
            account1: ctx.accounts.account1.to_account_info(),
            account2: ctx.accounts.account2.to_account_info(),
        },
    ),
)?;

// ✅ Good - Anchor
#[account]
pub account1: Account<'info, AccountType>,
#[account]
pub account2: Account<'info, AccountType>,
#[account]
pub other_program: Program<'info, OtherProgram>,
```
Impact: Incorrect account ordering in CPI calls can lead to unexpected behavior, unauthorized access, or program state corruption.

- [ ] Missing bump value in signer seeds
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

- [ ] Incorrect or missing seeds in signer seeds
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
Impact: Incorrect or missing seeds in signer seeds will cause PDA signature verification to fail, potentially allowing unauthorized access or causing transaction failures.

- [ ] Arbitrary CPI
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

### Unvalidated account 

- [ ] Missing check for rent account to be the same
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
- [ ] Missing check for token program
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
- [ ] Missing check for Sysvar account
```markdown
Clock: SysvarC1ock11111111111111111111111111111111
EpochSchedule: SysvarEpochSchedu1e111111111111111111111111
Fees: SysvarFees111111111111111111111111111111111
Instructions: Sysvar1nstructions1111111111111111111111111
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
- [ ] Missing check for Token Account Ownership
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

## Resources

### Official Documentation
- [ ] [Solana Program Security Course](https://solana.com/developers/courses/program-security)

### Security Best Practices
- [ ] [Token-2022 Security Best Practices](https://blog.offside.io/p/token-2022-security-best-practices-part-1)
- [ ] [Common Vulnerabilities in Anchor Programs](https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/)
- [ ] [A Hitchhiker's Guide to Solana Program Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- [ ] [Token-2022 Security Best Practices Part 2](https://blog.offside.io/p/token-2022-security-best-practices-part-2)
- [ ] [Solana Program Security Research](https://research.kudelskisecurity.com/2021/09/15/solana-program-security-part1/)
- [ ] [Solana Smart Contract Security Best Practices](https://github.com/slowmist/solana-smart-contract-security-best-practices)