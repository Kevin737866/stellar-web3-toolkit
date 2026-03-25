//! # Payment Channel Errors
//! 
//! Error types for the Stellar payment channel system.

use soroban_sdk::Error;

/// Payment channel specific errors
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum PaymentChannelError {
    /// Channel does not exist
    ChannelNotFound = 1,
    /// Invalid balance (negative or exceeds limits)
    InvalidBalance = 2,
    /// Balances don't match total
    BalanceMismatch = 3,
    /// Invalid timeout value
    InvalidTimeout = 4,
    /// Invalid fee percentage
    InvalidFee = 5,
    /// Insufficient balance for payment
    InsufficientBalance = 6,
    /// Unauthorized participant
    UnauthorizedParticipant = 7,
    /// HTLC not found
    HtlcNotFound = 8,
    /// HTLC already claimed
    HtlcAlreadyClaimed = 9,
    /// HTLC already refunded
    HtlcAlreadyRefunded = 10,
    /// HTLC has expired
    HtlcExpired = 11,
    /// HTLC has not expired yet
    HtlcNotExpired = 12,
    /// Invalid preimage provided
    InvalidPreimage = 13,
    /// Invalid HTLC amount
    InvalidHtlcAmount = 14,
    /// Invalid timelock value
    InvalidTimelock = 15,
    /// Invalid sequence number
    InvalidSequence = 16,
    /// Active HTLCs exist in channel
    ActiveHtlcsExist = 17,
    /// Channel is already closed
    ChannelAlreadyClosed = 18,
    /// Dispute period has not ended
    DisputePeriodActive = 19,
    /// Signature verification failed
    InvalidSignature = 20,
    /// Channel is not open
    ChannelNotOpen = 21,
    /// Invalid channel state
    InvalidChannelState = 22,
    /// Duplicate payment
    DuplicatePayment = 23,
    /// Payment too small (dust)
    PaymentBelowDustLimit = 24,
    /// Maximum HTLCs reached
    MaxHtlcsReached = 25,
    /// Channel reserve not met
    ReserveNotMet = 26,
    /// Routing failed
    RoutingFailed = 27,
    /// Path too long
    PathTooLong = 28,
    /// Amount exceeds maximum
    AmountExceedsMaximum = 29,
}

impl From<PaymentChannelError> for Error {
    fn from(e: PaymentChannelError) -> Self {
        Error::from_contract_error(e as u32)
    }
}

impl TryFrom<u32, Error> for PaymentChannelError {
    type Error = Error;
    
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PaymentChannelError::ChannelNotFound),
            2 => Ok(PaymentChannelError::InvalidBalance),
            3 => Ok(PaymentChannelError::BalanceMismatch),
            4 => Ok(PaymentChannelError::InvalidTimeout),
            5 => Ok(PaymentChannelError::InvalidFee),
            6 => Ok(PaymentChannelError::InsufficientBalance),
            7 => Ok(PaymentChannelError::UnauthorizedParticipant),
            8 => Ok(PaymentChannelError::HtlcNotFound),
            9 => Ok(PaymentChannelError::HtlcAlreadyClaimed),
            10 => Ok(PaymentChannelError::HtlcAlreadyRefunded),
            11 => Ok(PaymentChannelError::HtlcExpired),
            12 => Ok(PaymentChannelError::HtlcNotExpired),
            13 => Ok(PaymentChannelError::InvalidPreimage),
            14 => Ok(PaymentChannelError::InvalidHtlcAmount),
            15 => Ok(PaymentChannelError::InvalidTimelock),
            16 => Ok(PaymentChannelError::InvalidSequence),
            17 => Ok(PaymentChannelError::ActiveHtlcsExist),
            18 => Ok(PaymentChannelError::ChannelAlreadyClosed),
            19 => Ok(PaymentChannelError::DisputePeriodActive),
            20 => Ok(PaymentChannelError::InvalidSignature),
            21 => Ok(PaymentChannelError::ChannelNotOpen),
            22 => Ok(PaymentChannelError::InvalidChannelState),
            23 => Ok(PaymentChannelError::DuplicatePayment),
            24 => Ok(PaymentChannelError::PaymentBelowDustLimit),
            25 => Ok(PaymentChannelError::MaxHtlcsReached),
            26 => Ok(PaymentChannelError::ReserveNotMet),
            27 => Ok(PaymentChannelError::RoutingFailed),
            28 => Ok(PaymentChannelError::PathTooLong),
            29 => Ok(PaymentChannelError::AmountExceedsMaximum),
            _ => Err(Error::from_contract_error(value)),
        }
    }
}

impl PaymentChannelError {
    /// Get the error message for this error
    pub fn message(&self) -> &'static str {
        match self {
            PaymentChannelError::ChannelNotFound => "Channel not found",
            PaymentChannelError::InvalidBalance => "Invalid balance provided",
            PaymentChannelError::BalanceMismatch => "Balances don't match total",
            PaymentChannelError::InvalidTimeout => "Invalid timeout value",
            PaymentChannelError::InvalidFee => "Invalid fee percentage",
            PaymentChannelError::InsufficientBalance => "Insufficient balance for payment",
            PaymentChannelError::UnauthorizedParticipant => "Unauthorized participant",
            PaymentChannelError::HtlcNotFound => "HTLC not found",
            PaymentChannelError::HtlcAlreadyClaimed => "HTLC already claimed",
            PaymentChannelError::HtlcAlreadyRefunded => "HTLC already refunded",
            PaymentChannelError::HtlcExpired => "HTLC has expired",
            PaymentChannelError::HtlcNotExpired => "HTLC has not expired yet",
            PaymentChannelError::InvalidPreimage => "Invalid preimage provided",
            PaymentChannelError::InvalidHtlcAmount => "Invalid HTLC amount",
            PaymentChannelError::InvalidTimelock => "Invalid timelock value",
            PaymentChannelError::InvalidSequence => "Invalid sequence number",
            PaymentChannelError::ActiveHtlcsExist => "Active HTLCs exist in channel",
            PaymentChannelError::ChannelAlreadyClosed => "Channel is already closed",
            PaymentChannelError::DisputePeriodActive => "Dispute period is still active",
            PaymentChannelError::InvalidSignature => "Invalid signature provided",
            PaymentChannelError::ChannelNotOpen => "Channel is not open",
            PaymentChannelError::InvalidChannelState => "Invalid channel state",
            PaymentChannelError::DuplicatePayment => "Duplicate payment detected",
            PaymentChannelError::PaymentBelowDustLimit => "Payment amount below dust limit",
            PaymentChannelError::MaxHtlcsReached => "Maximum number of HTLCs reached",
            PaymentChannelError::ReserveNotMet => "Channel reserve not met",
            PaymentChannelError::RoutingFailed => "Routing failed",
            PaymentChannelError::PathTooLong => "Payment path too long",
            PaymentChannelError::AmountExceedsMaximum => "Amount exceeds maximum allowed",
        }
    }
}
