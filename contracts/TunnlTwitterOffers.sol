// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AutomationCompatibleInterface} from "@chainlink/contracts/src/v0.8/automation/AutomationCompatible.sol";
import {FunctionsClient} from "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/FunctionsClient.sol";
import {FunctionsRequest} from "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/libraries/FunctionsRequest.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20WithPermit} from "./interface/IERC20WithPermit.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import {ITunnlTwitterOffers} from "./interface/ITunnlTwitterOffers.sol";

contract TunnlTwitterOffers is FunctionsClient, AutomationCompatibleInterface, Ownable {
    /**
     * @notice Tunnl Twitter Offer contract
     * Actors of the protocol : Advertisers, Admins, Owner, Creators
     * Users : Advertisers & Creators
     * Owner can only be 1 --> Ownable contract
     * Admin can be multiple
     * only owner should add or remove admin
     * protocol does not take custody of funds (in this case USDC of users)
     */
    using FunctionsRequest for FunctionsRequest.Request;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using SafeERC20 for IERC20WithPermit;

    /////////STATE VARIABLES///////

    IERC20WithPermit private usdcToken;
    EnumerableSet.Bytes32Set private s_offersToUpkeep; // Set of offerIds that need to be expired, verified or paid out

    string public constant version = "TunnlTwitterOffers 1.0.0";
    address private s_owner; // The address of the contract deployer
    ITunnlTwitterOffers.Config public s_config; // The configuration for the contract which can be set by the admins

    mapping(bytes32 offerId => ITunnlTwitterOffers.Offer) private s_offers; // Maps from the offerId to the offer struc
    mapping(bytes32 functionsRequestId => bytes32 offerId) private s_functionsRequests; // Maps from the Chainlink Functions request ID to the offer ID
    mapping(address admin => bool) private s_admins; // Maps from the address of an admin to a boolean indicating if they are an admin

    ///////////EVENTS//////////

    event Created(bytes32 indexed offerId, ITunnlTwitterOffers.Offer offer);
    event Accepted(bytes32 indexed offerId, uint32 payoutDate, address contentCreator);
    event Submitted(bytes32 indexed offerId);
    event RequestSent(
        bytes32 indexed offerId,
        bytes32 indexed functionsRequestId,
        ITunnlTwitterOffers.Status offerStatus
    );
    event Response(
        bytes32 indexed offerId,
        bytes32 indexed functionsRequestId,
        ITunnlTwitterOffers.Status previousStatus,
        ITunnlTwitterOffers.Status newStatus
    );
    event OfferStatus(
        bytes32 indexed offerId, ITunnlTwitterOffers.Status previousStatus, ITunnlTwitterOffers.Status currentStatus
    );
    event PreviousConfig(ITunnlTwitterOffers.Config previousConfig);
    event PreviousOffer(bytes32 indexed offerId, ITunnlTwitterOffers.Offer previousOffer);

    ///////////MODIFIERS///////////

    modifier onlyAdmins() { // @audit
        require(s_admins[msg.sender] || msg.sender == s_owner, "Not admin");
        _;
    }

    modifier onlyAdminOrParticipant(bytes32 offerId) {
        require(
            msg.sender == s_offers[offerId].advertiser ||
            msg.sender == s_offers[offerId].contentCreator ||
            s_admins[msg.sender],
            "Not Advertiser/ContentCreator or Admin"
        );
        _;
    }

    modifier isValidOffer(ITunnlTwitterOffers.CreateOfferStruct[] memory offers) {
        for(uint i = offers.length; i < offers.length; i++) {
            bytes32 _offerId = offers[i].offerId;
            require(offers[i].offerId != bytes32(0), "Invalid offerId");
            require(offers[i].acceptanceDurationSeconds >= s_config.minAcceptanceDurationSeconds, "AcceptanceDuration is too short");
            require(offers[i].offerDurationSeconds >= s_config.minOfferDurationSeconds, "OfferDuration is too short");
            require(s_offers[_offerId].creationDate == 0, "Offer already exists");
        }
        _;
    }

    constructor(address _functionsRouter, address _usdcToken, ITunnlTwitterOffers.Config memory _config)
    FunctionsClient(_functionsRouter)
    Ownable(msg.sender) {
        usdcToken = IERC20WithPermit(_usdcToken);
        s_admins[msg.sender] = true;
        s_owner = msg.sender;
        s_config = _config;
    }

    ////////EXTERNAL FUNCTIONS/////////

    /*
    * @notice This is called by the advertiser's wallet to create an offer
    * @param offerId The unique identifier for the offer
    * @param maxPaymentUsdc The maximum payment the content creator can receive in USDC
    * @param acceptanceDurationSeconds The duration in seconds that the offer is open for acceptance after being created
    * @param _offerDurationSeconds Is the number of seconds after the creator accepts an offer before the offer either expires or receives a successful payout
    */
    function createOffer(bytes32 offerId, uint256 maxPaymentUsdc, uint32 acceptanceDurationSeconds, uint32 _offerDurationSeconds) public {

        require(offerId != bytes32(0), "Invalid offerId");
        require(s_offers[offerId].creationDate == 0, "Offer already exists");
        require(acceptanceDurationSeconds >= s_config.minAcceptanceDurationSeconds, "AcceptanceDuration is too short");
        require(_offerDurationSeconds >= s_config.minOfferDurationSeconds, "OfferDuration is too short");

        uint256 percentageFeeUsdc = (uint256(maxPaymentUsdc) * uint256(s_config.advertiserFeePercentageBP)) / 10000;
        uint256 maxValueUsdc = maxPaymentUsdc + s_config.flatFeeUsdc + percentageFeeUsdc;
        require(usdcToken.allowance(msg.sender, address(this)) >= maxValueUsdc, "Insufficient USDC allowance");
        require(usdcToken.balanceOf(msg.sender) >= maxValueUsdc, "Insufficient USDC balance");

        s_offers[offerId] = ITunnlTwitterOffers.Offer({
            status: ITunnlTwitterOffers.Status.Pending,
            flatFeeUsdc: s_config.flatFeeUsdc,
            advertiserFeePercentageBP: s_config.advertiserFeePercentageBP,
            creatorFeePercentageBP: s_config.creatorFeePercentageBP,
            maxValueUsdc: maxValueUsdc,
            creationDate: uint32(block.timestamp),
            acceptanceExpirationDate: uint32(block.timestamp) + acceptanceDurationSeconds,
            advertiser: msg.sender,
            contentCreator: address(0),
            payoutDate: 0,
            dateToAttemptVerification: 0,
            verificationFailureMessage: "",
            payoutFailureMessage: "",
            amountPaidUsdc: 0,
            offerDurationSeconds : _offerDurationSeconds
        });
        s_offersToUpkeep.add(offerId);
        emit Created(offerId, s_offers[offerId]);
    }

    function createOfferWithPermit(
            bytes32 offerId, 
            address brand, 
            uint256 maxPaymentUsdc,  
            uint32 acceptanceDurationSeconds, 
            uint32 _offerDurationSeconds,
            uint256 deadline,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) external {
            require(offerId != bytes32(0), "Invalid offerId");
            require(s_offers[offerId].creationDate == 0, "Offer already exists");
            require(acceptanceDurationSeconds >= s_config.minAcceptanceDurationSeconds, "AcceptanceDuration is too short");
            require(_offerDurationSeconds >= s_config.minOfferDurationSeconds, "OfferDuration is too short");

            uint256 percentageFeeUsdc = (uint256(maxPaymentUsdc) * uint256(s_config.advertiserFeePercentageBP)) / 10000;
            uint256 maxValueUsdc = maxPaymentUsdc + s_config.flatFeeUsdc + percentageFeeUsdc;

            // Use permit to approve the contract to spend USDC on behalf of the brand
            usdcToken.permit(msg.sender, address(this), maxValueUsdc, deadline, v, r, s);

            require(usdcToken.allowance(brand, address(this)) >= maxValueUsdc, "Insufficient USDC allowance");
            require(usdcToken.balanceOf(brand) >= maxValueUsdc, "Insufficient USDC balance");

            s_offers[offerId] = ITunnlTwitterOffers.Offer({
                status: ITunnlTwitterOffers.Status.Pending,
                flatFeeUsdc: s_config.flatFeeUsdc,
                advertiserFeePercentageBP: s_config.advertiserFeePercentageBP,
                creatorFeePercentageBP: s_config.creatorFeePercentageBP,
                maxValueUsdc: maxValueUsdc,
                creationDate: uint32(block.timestamp),
                acceptanceExpirationDate: uint32(block.timestamp) + acceptanceDurationSeconds,
                advertiser: brand,
                contentCreator: address(0),
                payoutDate: 0,
                dateToAttemptVerification: 0,
                verificationFailureMessage: "",
                payoutFailureMessage: "",
                amountPaidUsdc: 0,
                offerDurationSeconds : _offerDurationSeconds
            });
            s_offersToUpkeep.add(offerId);
            emit Created(offerId, s_offers[offerId]);
    }

    function batchCreateOffers(ITunnlTwitterOffers.CreateOfferStruct[] memory offers) 
        isValidOffer(offers)
        external {
            require(offers.length <= 4, "Too many offers in a single batch");
            for(uint i = 0; i < offers.length; i++) {
                createOffer(offers[i].offerId, offers[i].maxPaymentUsdc, offers[i].acceptanceDurationSeconds, offers[i].offerDurationSeconds);
            }
    }

    /*
    * @notice This is called by the backend in order to verify that the offer was actually sent to the content creator who is trying to accept the offer
    * It also prevents the content creator from needing to pay gas to accept the offer
    * @param offerId The unique identifier for the offer
    * @param contentCreator The address of the content creator
    */
    function acceptOffer(bytes32 offerId, address contentCreator) external onlyAdmins {
        require(s_offers[offerId].creationDate > 0, "Offer does not exist");
        require(s_offers[offerId].status == ITunnlTwitterOffers.Status.Pending, "Offer not pending");
        require(s_offers[offerId].acceptanceExpirationDate >= block.timestamp, "Offer expired");
        require(
            usdcToken.allowance(s_offers[offerId].advertiser, address(this)) >= s_offers[offerId].maxValueUsdc,
            "Insufficient USDC allowance from advertiser"
        );
        require(usdcToken.balanceOf(s_offers[offerId].advertiser) >= s_offers[offerId].maxValueUsdc, "Insufficient USDC balance from advertiser");
        s_offers[offerId].status = ITunnlTwitterOffers.Status.Accepted;
        s_offers[offerId].payoutDate = uint32(block.timestamp) + s_offers[offerId].offerDurationSeconds;
        s_offers[offerId].contentCreator = contentCreator;
        // Transfer the USDC flat fee from the advertiser to the contract owner
        usdcToken.safeTransferFrom(s_offers[offerId].advertiser, s_owner, s_offers[offerId].flatFeeUsdc);
        // Transfer the max payment USDC from the advertiser to the contract to hold in escrow
        usdcToken.safeTransferFrom(
            s_offers[offerId].advertiser, address(this), s_offers[offerId].maxValueUsdc - s_offers[offerId].flatFeeUsdc
        );
        emit Accepted(offerId, s_offers[offerId].payoutDate, contentCreator);
    }

    /*
    * @notice This is called by the backend to prevent the content creator from needing to pay gas to submit the tweet for verification
    * @param verificationDelaySeconds The delay in seconds before the tweet verification is attempted by Chainlink Automation & Functions
    * This allows scheduling the verification request until after the tweet has been live for 1 hour such that it can no longer be edited
    */
    function submitTweet(bytes32 offerId, uint32 verificationDelaySeconds) external onlyAdmins {
        require(
            s_offers[offerId].status == ITunnlTwitterOffers.Status.Accepted || s_offers[offerId].status == ITunnlTwitterOffers.Status.VerificationFailed,
            "Invalid"
        );
        require(s_offers[offerId].payoutDate >= block.timestamp, "too late");
        require(verificationDelaySeconds <= s_config.maxVerificationDelaySeconds, "Delay too long");
        s_offers[offerId].status = ITunnlTwitterOffers.Status.AwaitingVerification;
        s_offers[offerId].dateToAttemptVerification = uint32(block.timestamp) + verificationDelaySeconds;
        emit Submitted(offerId);
    }

    /*
    * @notice This is called to cancel an offer. It can be called by the advertiser, content creator, or backend/admin
    * @param offerId The unique identifier for the offer
    * @note ensure only content creator can cancel an 'accepted' offer
    * @note ensure that, after an offer is accepted, it can only be cancelled by the content creator or admin
    */
    function cancelOffer(bytes32 offerId) external onlyAdminOrParticipant(offerId) {
        ITunnlTwitterOffers.Status previousStatus = s_offers[offerId].status;
        require(s_offers[offerId].status != ITunnlTwitterOffers.Status.Expired, "Offer Expired");
        require(s_offers[offerId].status != ITunnlTwitterOffers.Status.Cancelled, "Offer Cancelled");
        require(s_offers[offerId].status != ITunnlTwitterOffers.Status.Complete, "Offer Complete");
        s_offers[offerId].status = ITunnlTwitterOffers.Status.Cancelled;

        if (previousStatus == ITunnlTwitterOffers.Status.Pending) {
            require(msg.sender == s_offers[offerId].advertiser || s_admins[msg.sender], "Not advertiser or admin");
            s_offersToUpkeep.remove(offerId);
            _revokeAllowanceForPendingOffer(offerId);
        } else {
            require(msg.sender == s_offers[offerId].contentCreator || s_admins[msg.sender], "Not creator or admin");
            if (_hasFundsInEscrow(previousStatus)) {
                s_offersToUpkeep.remove(offerId);
                uint256 escrowedAmount = s_offers[offerId].maxValueUsdc - s_offers[offerId].flatFeeUsdc;
                usdcToken.safeTransfer(s_offers[offerId].advertiser, escrowedAmount);
            }
        }

        emit OfferStatus(offerId, previousStatus, s_offers[offerId].status);
    }

    /*
    * @notice This function is called in case of Twitter API failure, RPC issue, or any general
    * failure in order to manually retry functions request via admins based on status of offer
    * @param offerIds The offer Ids to be sent for batch manual retry request
    */
    function retryRequests(bytes32[] calldata offerIds) external onlyAdmins {
        for (uint256 i = 0; i < offerIds.length; i++) {
            bytes32 offerId = offerIds[i];

            // Check if the offer is eligible for a retry based on its status
            if (
                s_offers[offerId].status == ITunnlTwitterOffers.Status.VerificationFailed ||
                s_offers[offerId].status == ITunnlTwitterOffers.Status.VerificationInFlight ||
                s_offers[offerId].status == ITunnlTwitterOffers.Status.AwaitingVerification
            ) {
                sendFunctionsRequest(offerId, ITunnlTwitterOffers.RequestType.Verification);
            }
            if (
                s_offers[offerId].status == ITunnlTwitterOffers.Status.PayoutFailed ||
                s_offers[offerId].status == ITunnlTwitterOffers.Status.PayoutInFlight ||
                (s_offers[offerId].status == ITunnlTwitterOffers.Status.Active && s_offers[offerId].payoutDate <= block.timestamp)
            ) {
                sendFunctionsRequest(offerId, ITunnlTwitterOffers.RequestType.Payout);
            }
        }
    }


    /*
    @notice This onlyAdmin function is called in case creator / brands wants the admin to manually verify the tweet.
            This can be useful in case of AI's response returning faulty or incorrect results.
    @param offerId The offer Id to be manually verified
    @param isTweetVerified Whether the tweet passed 'Manual' verification by admin or not
    @note only 'Active' and 'VerificationFailed' statuses are eligible for manually verification
    @note in case there is a rate limit problem on CL functions, admins can directly call retryRequests() function
    */
    function setVerificationStatus(bytes32 offerId, bool isTweetVerified) external onlyAdmins {
        require(block.timestamp < s_offers[offerId].payoutDate, "Expired");
        require(s_offers[offerId].status == ITunnlTwitterOffers.Status.Accepted || s_offers[offerId].status == ITunnlTwitterOffers.Status.AwaitingVerification || s_offers[offerId].status == ITunnlTwitterOffers.Status.VerificationInFlight || s_offers[offerId].status == ITunnlTwitterOffers.Status.VerificationFailed || s_offers[offerId].status == ITunnlTwitterOffers.Status.Active, "Invalid Status");
        // check the current status of the offer
        if (s_offers[offerId].status == ITunnlTwitterOffers.Status.Active) {
            if (!isTweetVerified) { // only need to check here for the case where AI's response was incorrect
                s_offers[offerId].status = ITunnlTwitterOffers.Status.VerificationFailed;
            }
            return; // skip if the AI's response was correct, this is when the offer status is 'Active' and the AI has rightly verified it.
        }
        if(isTweetVerified){ // This is when offer is in any of the allowed statuses except 'Active'
            s_offers[offerId].status = ITunnlTwitterOffers.Status.Active;
        }
    }

    /////////EXTERNAL VIEW FUNCTIONS////////

    /* @notice CHAINLINK AUTOMATION INTEGRATION */
    /*
    * @notice Below are the Chainlink Automation function to get which offers need to be expired, verified or paid out
    * @param The input argument is not used
    * verification, expiration and payout requests are triggered here
    * There are 2 way by which function request may fail:
                    -- 1. If Chainlink function timeout exceeds ( > 5 minutes )
                    -- 2. If Chainlink functions return with an error
    *  Chainlink functions returns with an error by any of the 2 ways :-
                    -- 1. tweet invalid
    *               -- 2. api failure
    */
    function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory performData) {
        bytes32[] memory offersToUpkeep = new bytes32[](0);
        for (uint256 i = 0; i < s_offersToUpkeep.length(); i++) {
            bytes32 offerId = s_offersToUpkeep.at(i);
            if (
                _needsVerificationRequest(s_offers[offerId].status, s_offers[offerId].dateToAttemptVerification) ||
                _needsExpiration(s_offers[offerId].status, s_offers[offerId].payoutDate, s_offers[offerId].acceptanceExpirationDate) ||
                _needsPayoutRequest(s_offers[offerId].status, s_offers[offerId].payoutDate)
            ) {
                offersToUpkeep = appendOfferToUpkeep(offersToUpkeep, offerId);
                if (offersToUpkeep.length == s_config.automationUpkeepBatchSize) {
                    return (true, abi.encode(offersToUpkeep));
                }
            }
        }
        return (offersToUpkeep.length > 0, abi.encode(offersToUpkeep));
    }

    /*
    * @notice Chainlink Automation function to expire offers or send Chainlink Functions requests to verify tweets or calculate payments and pay content creators
    * @param performData The array of offerIds that need to be expired, verified or paid out
    * @dev All Function requests are sent through automation
    */
    function performUpkeep(bytes calldata performData) external override {
        bytes32[] memory offersToUpkeep = abi.decode(performData, (bytes32[]));

        for (uint256 i = 0; i < offersToUpkeep.length; i++) {
            bytes32 offerId = offersToUpkeep[i];

            if (_needsVerificationRequest(s_offers[offerId].status, s_offers[offerId].dateToAttemptVerification)) {
                sendFunctionsRequest(offerId, ITunnlTwitterOffers.RequestType.Verification);
            } else if (_needsExpiration(s_offers[offerId].status, s_offers[offerId].payoutDate, s_offers[offerId].acceptanceExpirationDate)) {
                // Update status before making the external call
                ITunnlTwitterOffers.Status previousStatus = s_offers[offerId].status;
                s_offers[offerId].status = ITunnlTwitterOffers.Status.Expired;
                s_offersToUpkeep.remove(offerId);
                if (previousStatus == ITunnlTwitterOffers.Status.Pending) {
                    // If expired BEFORE offer is accepted & funds have been locked in escrow, "revoke" the allowance by sending the advertiser's funds back to themselves
                    _revokeAllowanceForPendingOffer(offerId);
                } else {
                    // If expired AFTER offer is accepted & funds have been locked in escrow, release the funds in escrow back to the advertiser
                    uint256 amountToTransfer = s_offers[offerId].maxValueUsdc - s_offers[offerId].flatFeeUsdc;
                    usdcToken.safeTransfer(s_offers[offerId].advertiser, amountToTransfer);
                }
                emit OfferStatus(offerId, previousStatus, ITunnlTwitterOffers.Status.Expired);
            } else if (_needsPayoutRequest(s_offers[offerId].status, s_offers[offerId].payoutDate)) {
                sendFunctionsRequest(offerId, ITunnlTwitterOffers.RequestType.Payout);
            }
        }
    }

    function setConfig(ITunnlTwitterOffers.Config calldata _config) external onlyOwner {
        emit PreviousConfig(s_config);
        s_config = _config;
    }

    //////////PRIVATE & INTERNAL FUNCTIONS////////

    /*  CHAINLINK FUNCTION INTEGRATION */

    /*
    * @notice This sends the Chainlink Functions request to either verify the tweet or calculate the payment and pay the content creator
    * @param offerId The unique identifier for the offer
    * @param ITunnlTwitterOffers.RequestType The type of request to send (Verification or Payout)
    */
    function sendFunctionsRequest(bytes32 offerId, ITunnlTwitterOffers.RequestType requestType) internal {
        FunctionsRequest.Request memory req;
        req.initializeRequest(
            FunctionsRequest.Location.Inline,
            FunctionsRequest.CodeLanguage.JavaScript,
            requestType == ITunnlTwitterOffers.RequestType.Verification
                ? s_config.functionsVerificationRequestScript
                : s_config.functionsPayoutRequestScript
        );
        req.secretsLocation = FunctionsRequest.Location.Remote;
        req.encryptedSecretsReference = s_config.functionsEncryptedSecretsReference;

        uint256 maxCreatorPayment = uint256((s_offers[offerId].maxValueUsdc - s_offers[offerId].flatFeeUsdc) * 10000)
            / uint256(10000 + s_offers[offerId].advertiserFeePercentageBP);

        bytes[] memory bytesArgs = new bytes[](4);
        bytesArgs[0] = abi.encode(offerId);
        bytesArgs[1] = abi.encodePacked(s_offers[offerId].creationDate);
        bytesArgs[2] = abi.encodePacked(maxCreatorPayment);
        bytesArgs[3] = abi.encodePacked(s_offers[offerId].offerDurationSeconds);
        req.setBytesArgs(bytesArgs);

        bytes32 requestId = _sendRequest(
            req.encodeCBOR(),
            s_config.functionsSubscriptionId,
            s_config.functionsCallbackGasLimit,
            s_config.functionsDonId
        );
        s_functionsRequests[requestId] = offerId;
        s_offers[offerId].status = requestType == ITunnlTwitterOffers.RequestType.Verification
            ? ITunnlTwitterOffers.Status.VerificationInFlight
            : ITunnlTwitterOffers.Status.PayoutInFlight;
        emit RequestSent(offerId, requestId, s_offers[offerId].status);
    }
    /*
    * @notice This is called by the Chainlink Functions service to fulfill the tweet verification or payment calculation and payout request
    * @param requestId The Chainlink Functions request ID
    * @param response The response from the Chainlink Functions service
    * @param err The error message from the Chainlink Functions service
    */
    function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory err) internal override {
        bytes32 offerId = s_functionsRequests[requestId];
        delete s_functionsRequests[requestId];
        ITunnlTwitterOffers.Status previousStatus = s_offers[offerId].status;
        if (
            s_offers[offerId].status == ITunnlTwitterOffers.Status.VerificationInFlight
            || s_offers[offerId].status == ITunnlTwitterOffers.Status.AwaitingVerification
        ) {
            if (err.length > 0) {
                // If the creator tried to submit another tweet,
                // the offer status will be AwaitingVerification so that another Chainlink Functions
                // verification request will be sent
                s_offers[offerId].status = s_offers[offerId].status == ITunnlTwitterOffers.Status.AwaitingVerification
                    ? ITunnlTwitterOffers.Status.AwaitingVerification
                    : ITunnlTwitterOffers.Status.VerificationFailed;
                s_offers[offerId].verificationFailureMessage = string(err);
            } else {
                s_offers[offerId].status = ITunnlTwitterOffers.Status.Active;
            }
        }
        if (s_offers[offerId].status == ITunnlTwitterOffers.Status.PayoutInFlight) {
            if (err.length > 0) {
                s_offers[offerId].status = ITunnlTwitterOffers.Status.PayoutFailed;
                s_offers[offerId].payoutFailureMessage = string(err);
            } else {
                uint256 paymentEarnedUsdc = abi.decode(response, (uint256));
                s_offers[offerId].status = ITunnlTwitterOffers.Status.Complete;
                s_offersToUpkeep.remove(offerId);
                uint256 advertiserPercentageFee =
                    uint256(paymentEarnedUsdc * s_offers[offerId].advertiserFeePercentageBP) / 10000;
                uint256 creatorPercentageFee =
                    uint256(paymentEarnedUsdc * s_offers[offerId].creatorFeePercentageBP) / 10000;
                s_offers[offerId].amountPaidUsdc = paymentEarnedUsdc - creatorPercentageFee;
                require(
                    s_offers[offerId].amountPaidUsdc
                    <= s_offers[offerId].maxValueUsdc - s_offers[offerId].flatFeeUsdc - creatorPercentageFee
                    - advertiserPercentageFee,
                    "Exceeds max"
                );
                uint256 amountToReturnToAdvertiser = s_offers[offerId].maxValueUsdc - s_offers[offerId].amountPaidUsdc
                    - s_offers[offerId].flatFeeUsdc - creatorPercentageFee - advertiserPercentageFee;
                if (s_offers[offerId].amountPaidUsdc > 0) {
                    usdcToken.safeTransfer(s_owner, creatorPercentageFee + advertiserPercentageFee);
                    usdcToken.safeTransfer(s_offers[offerId].contentCreator, s_offers[offerId].amountPaidUsdc);
                }
                if (amountToReturnToAdvertiser > 0) {
                    usdcToken.safeTransfer(s_offers[offerId].advertiser, amountToReturnToAdvertiser);
                }
            }
        }
        emit Response(offerId, requestId, previousStatus, s_offers[offerId].status);
    }
    /*
    * @notice This is called to check if an offer has funds in escrow.
    * @param offerStatus Status of the Offer
    */
    function _hasFundsInEscrow(ITunnlTwitterOffers.Status offerStatus) internal pure returns (bool) {
        return (
            offerStatus == ITunnlTwitterOffers.Status.Accepted
            || offerStatus == ITunnlTwitterOffers.Status.AwaitingVerification
            || offerStatus == ITunnlTwitterOffers.Status.VerificationInFlight
            || offerStatus == ITunnlTwitterOffers.Status.VerificationFailed
            || offerStatus == ITunnlTwitterOffers.Status.Active
            || offerStatus == ITunnlTwitterOffers.Status.PayoutFailed
            || offerStatus == ITunnlTwitterOffers.Status.PayoutInFlight
        );
    }
    /*
    * @notice This is called to check whether the offer has expired or not
    * @notice The function checks if the offer is in the Pending status and the acceptanceExpirationDate has passed, or if the payout date has passed and the offer is in one of the following statuses (Accepted, AwaitingVerification, VerificationInFlight, VerificationFailed) and the payoutDate has passed.
    * @param offerStatus It is the status of the offer
    * @param payoutDate The date after which the payout will be attempted using Chainlink Automation & Functions
    */
    function _needsExpiration(ITunnlTwitterOffers.Status offerStatus, uint32 payoutDate, uint32 acceptanceExpirationDate) internal view returns (bool) {
        return (
            (acceptanceExpirationDate < block.timestamp && offerStatus == ITunnlTwitterOffers.Status.Pending) ||
            (payoutDate < block.timestamp &&
            (offerStatus == ITunnlTwitterOffers.Status.Accepted ||
            offerStatus == ITunnlTwitterOffers.Status.AwaitingVerification ||
            offerStatus == ITunnlTwitterOffers.Status.VerificationInFlight ||
            offerStatus == ITunnlTwitterOffers.Status.VerificationFailed))
        );
    }
    /*
    * @notice This is called to check whether the specific offer needs verification or not. If needed the status of the offer shall be updated.
    * @param offerStatus the Status of the offer
    * @param dateToAttemptVerification The date after which tweet verification will be attempted using Chainlink Automation & Functions
    */
    function _needsVerificationRequest(ITunnlTwitterOffers.Status offerStatus, uint32 dateToAttemptVerification) internal view returns(bool){
        return (
            (dateToAttemptVerification <= block.timestamp &&
            offerStatus == ITunnlTwitterOffers.Status.AwaitingVerification)
        );
    }
    /*
    * @notice This is called after successful verification to check whether now payout request should be sent or
    * @param offerStatus The current status of the offer
    * @param payoutDate  The date after which the payout will be attempted using Chainlink Automation & Functions
    */
    function _needsPayoutRequest(
        ITunnlTwitterOffers.Status offerStatus, uint32 payoutDate) internal view returns (bool) {
        return (
            (payoutDate <= block.timestamp && offerStatus == ITunnlTwitterOffers.Status.Active)
        );
    }
    /*
    * @notice This is called to revoke the allowance by transferring the approved tokens from the advertiser back to themselves
    * usdcToken.safeTransferFrom should NEVER revert
    * In the event the user's balance or allowance is less than the max value of the offer, the lesser amount is transferred
    * @param offerId The unique identifier for the offer
    */
    function _revokeAllowanceForPendingOffer(bytes32 offerId) internal {
        uint256 spendableAmount = Math.min(
            usdcToken.balanceOf(s_offers[offerId].advertiser),
            usdcToken.allowance(s_offers[offerId].advertiser, address(this))
        );
        uint256 amountToRevoke = Math.min(
            s_offers[offerId].maxValueUsdc,
            spendableAmount
        );
        usdcToken.safeTransferFrom(s_offers[offerId].advertiser, s_offers[offerId].advertiser, amountToRevoke);
    }
    /*
        * @notice Appends an offer to the array of offers that need upkeep from Chainlink Automation
        * @param offers The array of offerIds that need upkeep
        * @param offerId The unique identifier for the offer
    */
    function appendOfferToUpkeep(bytes32[] memory offers, bytes32 offerId) private pure returns (bytes32[] memory) {
        bytes32[] memory newOffers = new bytes32[](offers.length + 1);
        for (uint256 i = 0; i < offers.length; i++) {
            newOffers[i] = offers[i];
        }
        newOffers[offers.length] = offerId;
        return newOffers;
    }

    //  Owner Operations

    function addAdmin(address _admin) external onlyOwner {
        s_admins[_admin] = true;
    }

    function removeAdmin(address _admin) external onlyOwner {
        s_admins[_admin] = false;
    }

    /*  GETTERS */

    function getOffers(bytes32[] calldata offerIds) external view returns (ITunnlTwitterOffers.Offer[] memory) {
        ITunnlTwitterOffers.Offer[] memory offers = new ITunnlTwitterOffers.Offer[](offerIds.length);
        for (uint256 i = 0; i < offerIds.length; i++) {
            offers[i] = s_offers[offerIds[i]];
        }
        return offers;
    }

    function getConfig() public view returns (ITunnlTwitterOffers.Config memory) {
        return s_config;
    }
}