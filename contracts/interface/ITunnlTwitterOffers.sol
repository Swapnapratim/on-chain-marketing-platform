// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITunnlTwitterOffers {
    
    struct Config {
    uint8 automationUpkeepBatchSize; // The number of offers to expire, verify, or pay out in a single upkeep call
    uint16 advertiserFeePercentageBP; // Percentage fee of total paid to advertiser. Denoted in basis points where 1% = 100 basis points
    uint16 creatorFeePercentageBP; // Percentage fee of total paid to content creator. Denoted in basis points where 1% = 100 basis points
    uint24 functionsCallbackGasLimit; // The amount of gas that will be available for the fulfillment callback for the Chainlink Functions requests
    uint32 flatFeeUsdc; // Flat fee charged when the offer is accepted. Note: USDC uses 6 decimal points such that 1 USDC = 1 * 10^6. This means a config value of 1000000 represents 1 USDC.
    uint32 minOfferDurationSeconds; // sufficient period for the involved participants to fulfill their obligations and complete necessary tasks.
    uint32 minAcceptanceDurationSeconds; // The minimum duration in seconds that the offer is open for acceptance after being created
    uint32 maxVerificationDelaySeconds; // The maximum delay in seconds before the tweet verification is attempted by Chainlink Automation & Functions
    uint64 functionsSubscriptionId; // The subscription ID that will be charged to service the Chainlink Functions requests
    bytes32 functionsDonId; // The DON ID that will be charged to service the Chainlink Functions requests
    bytes functionsEncryptedSecretsReference; // The reference to the encrypted secrets for the Chainlink Functions requests
    string functionsVerificationRequestScript; // The JavaScript source code for the Chainlink Functions request to verify the tweet
    string functionsPayoutRequestScript; // The JavaScript source code for the Chainlink Functions request to calculate the payment and pay the content creator
    }

    enum Status {
        Pending, // Initial state after creation
        Accepted, // Advertiser funds are locked in escrow after the content creator accepts, flat fee has been transferred to the contract owner & payout date has been set for s_config.offerDurationSeconds from the acceptance date
        AwaitingVerification, // Indicates a tweet has been submitting and is awaiting verification from Chainlink Automation & Functions
        VerificationInFlight, // Indicates a Chainlink Functions request has been sent to verify the tweet
        VerificationFailed, // Indicates the tweet verification failed with an error message
        Active, // Indicates the tweet has been verified and the offer is active
        PayoutInFlight, // Indicates a Chainlink Functions request has been sent to calculate the payment and pay the content creator
        PayoutFailed, // Indicates the payment calculation and payout failed with an error message
        Complete, // Indicates the offer is complete and the content creator has been paid, percentage fee has been transferred to the contract owner & the remaining escrowed funds returned to the advertiser
        Expired, // Offers are expired via Chainlink Automation after acceptance once the payout date has passed such that the escrowed funds are released back to the advertiser
        Cancelled // Admins can cancel an offer any time after acceptance and before completion or expiration. Advertisers can only cancel before acceptance. Content creators can cancel any time before completion or expiration.
    }

    struct Offer {
        Status status; // The status of the offer
        uint16 advertiserFeePercentageBP; // Stores the percentage fee at the time the offer was created
        uint16 creatorFeePercentageBP; // Stores the percentage fee at the time the offer was created
        address advertiser; // The address of the advertiser
        address contentCreator; // The address of the content creator
        uint32 flatFeeUsdc; // Stores the flat fee at the time the offer was created
        uint32 creationDate; // The date the offer was created onchain
        uint32 acceptanceExpirationDate; // The date after which the offer can no longer be accepted
        uint32 payoutDate; // The date after which the payout will be attempted using Chainlink Automation & Functions
        uint32 dateToAttemptVerification; // The date after which tweet verification will be attempted using Chainlink Automation & Functions
        uint256 maxValueUsdc; // Percentage fee + flat fee + maximum payment the content creator can receive in USDC
        uint256 amountPaidUsdc; // The final amount paid to the content creator in USDC
        string verificationFailureMessage; // The error message for the tweet verification failure
        string payoutFailureMessage; // The error message for the payment calculation and payout failure
        uint32 offerDurationSeconds; // The duration in seconds after an offer  @audit added here instead of being in Config
    }

    struct CreateOfferStruct {
        bytes32 offerId;
        address brand;
        uint256 maxPaymentUsdc;
        uint32 acceptanceDurationSeconds;
        uint32 offerDurationSeconds;
    }

    enum RequestType {
        Verification,
        Payout
    }

    function createOfferWithPermit(
        bytes32 offerId,
        address brand,
        uint256 maxPaymentUsdc,
        uint32 acceptanceDurationSeconds,
        uint32 offerDurationSeconds
    ) external;

    function getConfig() external view returns (Config memory);
}
