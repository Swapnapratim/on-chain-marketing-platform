// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";

import {TunnlTwitterOffers} from "../contracts/TunnlTwitterOffers.sol";
import {MockFunctionsRouter} from "./MockFunctionsRouter.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import "../node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "forge-std/StdCheats.sol";
import "forge-std/Vm.sol";
import {SigUtils} from "./utils.sol";
import {ITunnlTwitterOffers} from "../contracts/interface/ITunnlTwitterOffers.sol";

contract MockERC20 is ERC20, EIP712, ERC20Permit {

    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }


    uint8 private immutable _decimals;
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    constructor(string memory name, string memory symbol, uint8 decimalsArg) 
        ERC20(name, symbol)
        ERC20Permit(name)
    {
        _decimals = decimalsArg;
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }
    function DOMAIN_SEPARATOR() public view override returns (bytes32) {
        return _domainSeparatorV4();
    }

    // computes the hash of a permit

    function getHash(bytes32 structHash) public view returns (bytes32) {
    return _hashTypedDataV4(structHash);
}
}
contract test_TunnlTwitterOffers is StdCheats, Test {
    struct InitOfferStruct {
        uint256 maxPaymentUsdc;
        uint32 acceptanceDurationSeconds;
    }

    error OwnableUnauthorizedAccount(address account);

    MockFunctionsRouter public mockFunctionsRouter;
    MockERC20 public mockUsdcToken;
    TunnlTwitterOffers public tunnlTwitterOffers;

    address owner = address(1);
    address admin = address(2);
    address advertiser = address(3);
    address contentCreator = address(4);
    address unknown = address(5);

    bytes32 offerId = bytes32(uint(1));
    bytes32[] public offerIds;
    mapping(bytes32 offerId => bytes32 functionsRequestId) functionsRequestIds;

    function setUp() public {
        vm.startPrank(owner);
        mockFunctionsRouter = new MockFunctionsRouter();
        mockUsdcToken = new MockERC20("USDC", "USDC", 6);
        ITunnlTwitterOffers.Config memory config = ITunnlTwitterOffers.Config({
            flatFeeUsdc: 5_000_000, // 5 USDC
            advertiserFeePercentageBP: 500, // 5%
            creatorFeePercentageBP: 250, // 2.5%
            minOfferDurationSeconds: 48 * 60 * 60, // 2 days
            minAcceptanceDurationSeconds: 60 * 60 * 24 * 3, // 3 days
            maxVerificationDelaySeconds: 60 * 60, // 1 hour
            automationUpkeepBatchSize: 4,
            functionsEncryptedSecretsReference: bytes("test"),
            functionsCallbackGasLimit: 300000,
            functionsSubscriptionId: 8,
            functionsDonId: bytes32(0x66756e2d73746167696e672d626173652d7365706f6c69612d31000000000000),
            functionsVerificationRequestScript: "test",
            functionsPayoutRequestScript: "test"
        });
        tunnlTwitterOffers = new TunnlTwitterOffers(address(mockFunctionsRouter), address(mockUsdcToken), config);
        tunnlTwitterOffers.addAdmin(admin);

        offerIds.push(bytes32(uint256(1)));
        offerIds.push(bytes32(uint256(2)));

        vm.stopPrank();
    }

    function test_CreateOffer(uint256 maxPaymentUsdc, uint32 acceptanceDurationSeconds) public {
        vm.assume(getOffer(offerId).creationDate == 0);
        vm.assume(acceptanceDurationSeconds >= tunnlTwitterOffers.getConfig().minAcceptanceDurationSeconds);
        vm.assume(acceptanceDurationSeconds + block.timestamp < type(uint32).max);
        vm.assume(maxPaymentUsdc  <= type(uint128).max);

        _giveFundsAndCreateOffer(maxPaymentUsdc, acceptanceDurationSeconds);

        assertEq(uint(getOffer(offerId).status), 0);
        assertEq(getOffer(offerId).flatFeeUsdc, tunnlTwitterOffers.getConfig().flatFeeUsdc);
        assertEq(getOffer(offerId).advertiserFeePercentageBP, tunnlTwitterOffers.getConfig().advertiserFeePercentageBP);
        assertEq(
            getOffer(offerId).maxValueUsdc,
            maxPaymentUsdc + (
                (uint256(maxPaymentUsdc) * uint256(tunnlTwitterOffers.getConfig().advertiserFeePercentageBP)) / 10000
            ) + tunnlTwitterOffers.getConfig().flatFeeUsdc
        );
        assertEq(getOffer(offerId).creationDate, block.timestamp);
        assertEq(getOffer(offerId).acceptanceExpirationDate, block.timestamp + acceptanceDurationSeconds);
        assertEq(getOffer(offerId).advertiser, advertiser);
    }

    function test_CreateOffer_NotEnoughFunds(uint256 maxPaymentUsdc, uint32 acceptanceDurationSeconds) public {
        vm.assume(getOffer(offerId).creationDate == 0);
        vm.assume(acceptanceDurationSeconds >= tunnlTwitterOffers.getConfig().minAcceptanceDurationSeconds);
        vm.assume(acceptanceDurationSeconds + block.timestamp < type(uint32).max);
        vm.assume(maxPaymentUsdc  <= type(uint128).max);
        // Total value which is equal to the maximum payment to the content creator plus all the fees
        uint maxValueUsdc = maxPaymentUsdc + ((uint256(maxPaymentUsdc) * uint256(tunnlTwitterOffers.getConfig().advertiserFeePercentageBP)) / 10000) + tunnlTwitterOffers.getConfig().flatFeeUsdc;
        // Create an offer as the advertiser
        vm.startPrank(advertiser);
        mockUsdcToken.mint(advertiser, maxValueUsdc - 1);
        mockUsdcToken.approve(address(tunnlTwitterOffers), maxValueUsdc - 1);
        vm.stopPrank();

        vm.expectRevert(bytes("Insufficient USDC allowance"));
        tunnlTwitterOffers.createOffer(offerId, maxPaymentUsdc, acceptanceDurationSeconds, 4 days);
    }

    function test_AcceptOffer() public {
        uint256 maxPaymentUsdc = 100e6;
        uint32 acceptanceDurationSeconds = 60 * 60 * 24 * 3;

        vm.prank(advertiser);
        test_CreateOffer(maxPaymentUsdc, acceptanceDurationSeconds);

        vm.prank(admin);
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);

        assertEq(uint(getOffer(offerId).status), 1);
        assertEq(getOffer(offerId).contentCreator, contentCreator);
        // Verify the flatFeeUsdc was transferred to the owner
        assertEq(mockUsdcToken.balanceOf(owner), tunnlTwitterOffers.getConfig().flatFeeUsdc);
    }

    function test_AcceptOffer_NotEnoughFunds() public {
        uint256 maxPaymentUsdc = 100e6;
        uint32 acceptanceDurationSeconds = 60 * 60 * 24 * 3;

        vm.prank(advertiser);
        test_CreateOffer(maxPaymentUsdc, acceptanceDurationSeconds);

        vm.prank(advertiser);
        mockUsdcToken.approve(address(tunnlTwitterOffers), 0);

        vm.expectRevert(bytes("Insufficient USDC allowance from advertiser"));
        vm.prank(admin);
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
    }

    function test_SubmitTweet() public {
        uint256 maxPaymentUsdc = 100e6;
        uint32 acceptanceDurationSeconds = 60 * 60 * 24 * 3;

        vm.prank(advertiser);
        test_CreateOffer(maxPaymentUsdc, acceptanceDurationSeconds);

        vm.startPrank(admin);
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
        tunnlTwitterOffers.submitTweet(offerId, 100);
        vm.stopPrank();

        assertEq(getOffer(offerId).dateToAttemptVerification, block.timestamp + 100);
    }

    function test_SubmitTweet_AfterPayoutDate() public {
        uint256 maxPaymentUsdc = 100e6;
        uint32 acceptanceDurationSeconds = 60 * 60 * 24 * 3;

        vm.prank(advertiser);
        test_CreateOffer(maxPaymentUsdc, acceptanceDurationSeconds);

        vm.startPrank(admin);
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
        vm.stopPrank();

        // Move time forward past the payout date
        vm.warp(60 * 60 * 24 * 8);

        vm.prank(admin);
        vm.expectRevert(bytes("too late"));
        tunnlTwitterOffers.submitTweet(offerId, 100);
    }

    function test_CreateOffer_OfferId_Cannot_Be_Zero() public {
        vm.expectRevert("Invalid offerId");
        tunnlTwitterOffers.createOffer(bytes32(0), 100e6, 259200, 4 days);
    }

    function test_Creation_Date_Cannot_Be_Overridden() public {
         // Set max payment amount
        uint256 maxPaymentUsdc = uint256(uint256(100e6));
        // Create an offer
        _giveFundsAndCreateOffer(maxPaymentUsdc, 259200);
        // Attempt to create an offer with the same ID and expect it to revert
        vm.expectRevert(bytes("Offer already exists"));
        tunnlTwitterOffers.createOffer(offerId, maxPaymentUsdc, 259200, 4 days);
    }
    function test_Acceptance_Duration_Cannot_Be_Short_And_Long() public {
        // Set max payment amount
        uint256 maxPaymentUsdc = uint256(uint256(10e6));
        // Attempt to create an offer with a duration shorter than minimum
        uint32 duration = uint32(
            tunnlTwitterOffers.getConfig().minAcceptanceDurationSeconds - 1
        );
        vm.expectRevert("AcceptanceDuration is too short");
        tunnlTwitterOffers.createOffer(offerId, maxPaymentUsdc, duration, 4 days);
    }

    function test_ShouldRequireOfferDurationToBeGreaterThanMinimumOfferDuration() external {
        uint256 maxPaymentUsdc = uint256(uint256(100e6));
        uint32 acceptanceDuration = uint32(tunnlTwitterOffers.getConfig().minAcceptanceDurationSeconds);
        uint32 offerDuration = 24 * 60 * 60;
        vm.expectRevert("OfferDuration is too short");
        tunnlTwitterOffers.createOffer(offerId, maxPaymentUsdc, acceptanceDuration, offerDuration);
    }

    function test_AcceptOffer_Not_Pending_Fail() public {
        // `test_AcceptOffer()` function properly sets up an offer
        test_AcceptOffer();
        // Attempt to accept the offer again, expecting it to revert
        vm.prank(admin);
        vm.expectRevert("Offer not pending");
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
    }
    function test_Offer_Acceptance_Duration_Expired_fail() public {
        // Set max payment amount
        uint256 maxPaymentUsdc = uint256(uint256(100e6));

         // Create an offer
        _giveFundsAndCreateOffer(maxPaymentUsdc, 259200);

         // Advance time to exceed acceptance duration
        vm.warp(block.timestamp + 259200 + 1);

        // Attempt to accept the expired offer and expect it to revert
        vm.prank(owner);
        vm.expectRevert(bytes("Offer expired"));
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
    }

    function test_AcceptOffer_Not_Exist_Fail() public {
       // Attempt to accept an offer that does not exist and expect it to revert
        vm.prank(admin);
        vm.expectRevert("Offer does not exist");
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
    }
    function test_Submit_Pending_Offer_Fail() public {
         // Set max payment amount
        uint256 maxPaymentUsdc = uint256(uint256(100e6));

         // Create an offer
        _giveFundsAndCreateOffer(maxPaymentUsdc, 259200);
        // Attempt to submit a tweet for the pending offer as admin and expect it to revert
        vm.prank(admin);
        vm.expectRevert("Invalid");
        tunnlTwitterOffers.submitTweet(offerId, 100);
    }
    function test_SubmitTweet_Pass_VerificationDelay_fail() public {
        // Set max payment amount and acceptance duration
        uint256 maxPaymentUsdc = 100;
        uint32 acceptanceDurationSeconds = 60 * 60 * 24 * 3;

        // Create an offer by advertiser
        vm.prank(advertiser);
        test_CreateOffer(maxPaymentUsdc, acceptanceDurationSeconds);

        // Accept the offer by admin
        vm.startPrank(admin);
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
        vm.stopPrank();

         // Attempt to submit a tweet with a verification delay that exceeds the maximum allowed delay
        uint32 verificationdelay = tunnlTwitterOffers.getConfig().maxVerificationDelaySeconds + 1 seconds;

        vm.prank(admin);
        vm.expectRevert(bytes("Delay too long"));
        tunnlTwitterOffers.submitTweet(
            offerId,
            verificationdelay
        );
    }

    function test_CancelOffer_Cancelled_Before_OfferAcceptance_By_Admin() public {
        // Create an offer
        _giveFundsAndCreateOffer(uint256(uint256(100e16)), 259200);
        uint256 originalBalance = mockUsdcToken.balanceOf(advertiser);

        // Cancel the offer by admin
        vm.prank(admin);
        tunnlTwitterOffers.cancelOffer(offerId);

        // Retrieve the offer and assert its status is cancelled
        ITunnlTwitterOffers.Offer memory offer = getOffer(
            offerId
        );
        assertEq(
            uint256(offer.status),
            uint256(ITunnlTwitterOffers.Status.Cancelled)
        );
        assertEq(mockUsdcToken.balanceOf(advertiser), originalBalance);
        assertEq(mockUsdcToken.allowance(advertiser, address(tunnlTwitterOffers)), 0);
    }
    function test_CancelOffer_Cancelled_Before_OfferAcceptance_By_Advertiser() public {
        // Create an offer
        _giveFundsAndCreateOffer(uint256(uint256(100e16)), 259200);

        // Cancel the offer by advertiser right after creation
        vm.prank(advertiser);
        tunnlTwitterOffers.cancelOffer(offerId);

        ITunnlTwitterOffers.Offer memory offer = getOffer(
            offerId
        );
        // Retrieve the offer and assert its status is cancelled
        assertEq(
            uint256(offer.status),
            uint256(ITunnlTwitterOffers.Status.Cancelled)
        );
    }

    function test_CancelOffer_By_Creator() public {
        // Accept an Offer
        test_AcceptOffer();

        // Retrieve the offer to verify it's in Accepted status
        ITunnlTwitterOffers.Offer memory offerBefore = getOffer(offerId);
        assertEq(uint256(offerBefore.status), uint256(ITunnlTwitterOffers.Status.Accepted));
        // Cancel the offer by content creator
        vm.prank(contentCreator);
        tunnlTwitterOffers.cancelOffer(offerId);
        // Retrieve the offer and assert its status is cancelled
        ITunnlTwitterOffers.Offer memory offerAfter = getOffer(offerId);
        assertEq(uint256(offerAfter.status), uint256(ITunnlTwitterOffers.Status.Cancelled));

        // Check balances after cancellation
        assertEq(mockUsdcToken.balanceOf(advertiser), 105e6);
        assertEq(mockUsdcToken.balanceOf(address(tunnlTwitterOffers)), 0);
        assertEq(mockUsdcToken.balanceOf(contentCreator), 0);
    }

    function test_CancelOffer_By_Unauthorized_User() public {
        // Create an offer
        _giveFundsAndCreateOffer(uint256(uint256(100e16)), 259200);

        address unauthorized = makeAddr("unauthorized");
         // Attempt to cancel the offer by an unauthorized user and expect a revert
        vm.prank(unauthorized);
        vm.expectRevert("Not Advertiser/ContentCreator or Admin");
        tunnlTwitterOffers.cancelOffer(offerId);
    }
    function test_CancelOffer_By_Advertiser_After_Acceptance() public {
        // Accept an offer
        test_AcceptOffer();
        // Attempt to cancel the offer by advertiser after acceptance
        vm.prank(advertiser);
        vm.expectRevert("Not creator or admin");
        tunnlTwitterOffers.cancelOffer(offerId);
    }
    function test_CancelOffer_By_Admin_After_Acceptance() public {
        // Accept an offer
        test_AcceptOffer();
        // Attempt to cancel the offer by advertiser after acceptance
        vm.prank(admin);
        tunnlTwitterOffers.cancelOffer(offerId);

        // Retrieve the offer and assert its status is cancelled
        ITunnlTwitterOffers.Offer memory offer = getOffer(
            offerId
        );
        assertEq(
            uint256(offer.status),
            uint256(ITunnlTwitterOffers.Status.Cancelled)
        );
        assertEq(mockUsdcToken.balanceOf(advertiser), 105e6);
        assertEq(mockUsdcToken.balanceOf(address(tunnlTwitterOffers)), 0);
        assertEq(mockUsdcToken.balanceOf(owner), 5e6);
    }

    function test_Verification_Success() public{
        // Define the amount to be paid in USDC
        uint256 amountPaidUsdc = uint256(uint256(100e6));

        // Create an offer
        _giveFundsAndCreateOffer(amountPaidUsdc, 259200);

        // Accept the offer, submit a tweet, and simulate Chainlink automation
        vm.startPrank(admin);
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
        tunnlTwitterOffers.submitTweet(offerId, 100);
        vm.stopPrank();

        // Warp time for verified tweets and perform Chainlink automation
        vm.warp(block.timestamp + 100);
       performUpkeep();

        // Fulfill request to verify tweet
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[offerId],
            "",
            ""
        );
        // Retrieve the offer and assert its status is changed to "Active"
        ITunnlTwitterOffers.Offer memory offer = getOffer(
            bytes32(uint256(1))
        );
          assertEq(
                uint256(offer.status),
                uint256(ITunnlTwitterOffers.Status.Active));
    }
     function test_Verification_Fail() public {
        // Define the amount to be paid in USDC
        uint256 amountPaidUsdc = uint256(uint256(100e6));

        // Create an offer
        _giveFundsAndCreateOffer(amountPaidUsdc, 259200);
         // Accept the offer, submit a tweet, and simulate Chainlink automation for tweet verification
        vm.startPrank(admin);
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
        tunnlTwitterOffers.submitTweet(offerId, 100);
        vm.stopPrank();
        // Warp time for tweet verification and perform Chainlink automation
        vm.warp(block.timestamp + 100);
        performUpkeep();
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[offerId],
            "",
            abi.encode("Invalid Tweet")
        );

         ITunnlTwitterOffers.Offer memory offer3 = getOffer(
             offerId
         );
         // Retrieve the offer and assert its status is changed to "VerificationFailed"
        assertEq(
            uint256(offer3.status),
            uint256(ITunnlTwitterOffers.Status.VerificationFailed)
        );

    }

    function test_PayOut() public {
        // Define the amount to be paid in USDC
        uint256 amountPaidUsdc = uint256(uint256(100e6));
        test_Verification_Success();
        // Warp time for payout and perform Chainlink automation
        vm.warp(block.timestamp + (1 weeks - 100));
        performUpkeep();
        // Fulfill request for payout  with PayOutamount
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[offerId],
            abi.encode(amountPaidUsdc),
            ""
        );

        // Assert balances after payout
        assertEq(mockUsdcToken.balanceOf(advertiser), 0);
        assertEq(mockUsdcToken.balanceOf(address(tunnlTwitterOffers)), (0));
        assertEq(
            mockUsdcToken.balanceOf(contentCreator),
            amountPaidUsdc - (amountPaidUsdc * tunnlTwitterOffers.getConfig().creatorFeePercentageBP) / 10000
        );
        ITunnlTwitterOffers.Offer memory offer = getOffer(offerId);
        assertEq(uint256(offer.status), uint256(ITunnlTwitterOffers.Status.Complete));
    }
    function test_PayOut_Fail() public {
        // Define the amount to be paid in USDC
        uint256 amountPaidUsdc = uint256(uint256(100e6));

        // Create an offer
        _giveFundsAndCreateOffer(amountPaidUsdc, 259200);
         // Accept the offer, submit a tweet, and simulate Chainlink automation for tweet verification
        vm.startPrank(admin);
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
        tunnlTwitterOffers.submitTweet(offerId, 100);
        vm.stopPrank();

        // Warp time for tweet verification and perform Chainlink automation
        vm.warp(block.timestamp + 100);
        performUpkeep();

        // Fulfill request to verify tweet
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[offerId],
            "",
            ""
        );
       // Warp time for payout for verified tweets and perform Chainlink automation
        vm.warp(block.timestamp + (1 weeks - 100));
        performUpkeep();

        // Fulfill request with payout failure message
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[offerId],
            "",
            bytes("Failed to fetch valid secrets")
        );

         // Retrieve the offer and assert its status is changed to "PayoutFailed"
        ITunnlTwitterOffers.Offer memory offer = getOffer(
            offerId
        );
        assertEq(
            uint256(offer.status),
            uint256(ITunnlTwitterOffers.Status.PayoutFailed)
        );
         // Calculate the percentage fee
        uint percentaefee = (amountPaidUsdc * uint256(offer.advertiserFeePercentageBP)) /
            10000;

        // Assert balances after payout failure
        assertEq(mockUsdcToken.balanceOf(advertiser), 0);

        assertEq(
            mockUsdcToken.balanceOf(address(tunnlTwitterOffers)),
            (amountPaidUsdc + percentaefee)
        );
        assertEq(mockUsdcToken.balanceOf(contentCreator), 0);
    }

    function test_GetOffer() public {

        // Create and accept four offers with unique IDs
        CreateOffer_AcceptOffer_And_SubmitTweet(makeAddr("advertiser1"), makeAddr("creator1"), 1);
        CreateOffer_AcceptOffer_And_SubmitTweet(makeAddr("advertiser2"), makeAddr("creator2"), 2);
        CreateOffer_AcceptOffer_And_SubmitTweet(makeAddr("advertiser3"), makeAddr("creator3"), 3);
        CreateOffer_AcceptOffer_And_SubmitTweet(makeAddr("advertiser4"), makeAddr("creator4"), 4);

        // Define the IDs of the offers
        bytes32[] memory ids = new bytes32[](4);
        ids[0] = bytes32(uint256(1));
        ids[1] = bytes32(uint256(2));
        ids[2] = bytes32(uint256(3));
        ids[3] = bytes32(uint256(4));

        // Retrieve the offers
        ITunnlTwitterOffers.Offer[] memory offers = tunnlTwitterOffers.getOffers(
            ids
        );
        // Assert that the length of the returned offers array is 4
        assertEq(offers.length, 4);
    }
    function test_GetConfig() public {
         // Retrieve the initial configuration and assert its values
        ITunnlTwitterOffers.Config memory config = tunnlTwitterOffers
            .getConfig();
        assertEq(config.functionsVerificationRequestScript, "test");
        assertEq(config.functionsPayoutRequestScript, "test");

         // Define the updated configuration
        ITunnlTwitterOffers.Config memory configUpdate = ITunnlTwitterOffers
            .Config({
                flatFeeUsdc: 5_000_000, // 5 USDC
                advertiserFeePercentageBP: 500, // 5%
                creatorFeePercentageBP: 250, // 2.5%
                minOfferDurationSeconds: 48 * 60 * 60, // 2 days
                minAcceptanceDurationSeconds: 60 * 60 * 24 * 3, // 1 day
                maxVerificationDelaySeconds: 60 * 60, // 1 hour
                automationUpkeepBatchSize: 4,
                functionsEncryptedSecretsReference: bytes("testUpadte"),
                functionsCallbackGasLimit: 300000,
                functionsSubscriptionId: 8,
                functionsDonId: bytes32(
                    0x66756e2d73746167696e672d626173652d7365706f6c69612d31000000000000
                ),
                functionsVerificationRequestScript: "testUpdate",
                functionsPayoutRequestScript: "testUpdate"
            });
          // Fail for non-admin call
        vm.expectRevert(); // @audit custom error expectRevert to be added
        tunnlTwitterOffers.setConfig(configUpdate);

        // Update the configuration by admin
        vm.prank(owner);
        tunnlTwitterOffers.setConfig(configUpdate);

        // Retrieve the updated configuration and assert its values
        ITunnlTwitterOffers.Config memory config2 = tunnlTwitterOffers.getConfig();
        assertEq(config2.functionsVerificationRequestScript, "testUpdate");
        assertEq(config2.functionsPayoutRequestScript, "testUpdate");
    }

    function test_RemoveAdmin() public {
        // Remove admin by owner
        vm.prank(owner);
        tunnlTwitterOffers.removeAdmin(admin);

        // Ensure removed admin cannot perform admin-only actions
        vm.prank(admin);
        vm.expectRevert("Not admin");
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
    }


    // needed for integration
    //advertiser
    address advertiser1 = makeAddr("advertiser1");
    address advertiser2 = makeAddr("advertiser2");
    address advertiser3 = makeAddr("advertiser3");
    address advertiser4 = makeAddr("advertiser4");
    address advertiser5 = makeAddr("advertiser5");
    //creator
    address creator1 = makeAddr("creator1");
    address creator2 = makeAddr("creator2");
    address creator3 = makeAddr("creator3");
    address creator4 = makeAddr("creator4");
    address creator5 = makeAddr("creator5");

    function test_Integration_With_ChainLink_success() public {
         // Create, accept, and submit 4 offers respectively
        CreateOffer_AcceptOffer_And_SubmitTweet(advertiser1, creator1, 1);
        CreateOffer_AcceptOffer_And_SubmitTweet(advertiser2, creator2, 2);
        CreateOffer_AcceptOffer_And_SubmitTweet(advertiser3, creator3, 3);
        CreateOffer_AcceptOffer_And_SubmitTweet(advertiser4, creator4, 4);

        //warp time for verification
        vm.warp(block.timestamp + 100);

        /////////////////// Simulating chainlink Automation  /////////////
        // check upkeep ///
        performUpkeep();

        // Fulfill requests to verify tweets for all 4 offers
        // OfferId(1)
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(1))],
            "",
            ""
        );
        // OfferId(2);
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(2))],
            "",
            ""
        );
        // OfferId(3);
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(3))],
            "",
            ""
        );
        // OfferId(4);
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(4))],
            "",
            ""
        );

        // The amount to be paid to creator, same value for all 4 offers
        uint256 amountPaidUsdc = 100e6;

        uint maxValueUsdc = amountPaidUsdc +
            ((uint256(amountPaidUsdc) *
                uint256(tunnlTwitterOffers.getConfig().advertiserFeePercentageBP)) /
                10000
            ) + tunnlTwitterOffers.getConfig().flatFeeUsdc;

        uint totalFunds_sent_to_Owner = (
            maxValueUsdc - amountPaidUsdc
            + (amountPaidUsdc * tunnlTwitterOffers.getConfig().creatorFeePercentageBP)
            / 10000
        ) * 4;

        ////////// warp time for payout for verified tweets ///////////////
        vm.warp(block.timestamp + (1 weeks - 100));
        performUpkeep();

        // OfferId(1);
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(1))],
            abi.encode(amountPaidUsdc),
            ""
        );

        // OfferId(2);
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(2))],
            abi.encode(amountPaidUsdc),
            ""
        );
        // OfferId(3);
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(3))],
            abi.encode(amountPaidUsdc),
            ""
        );

        // OfferId(4);
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(4))],
            abi.encode(amountPaidUsdc),
            ""
        );
        //assert creator get their exact funds
        assertEq(
            mockUsdcToken.balanceOf(creator1),
            amountPaidUsdc - (amountPaidUsdc * tunnlTwitterOffers.getConfig().creatorFeePercentageBP) / 10000
        );
        assertEq(
            mockUsdcToken.balanceOf(creator2),
            amountPaidUsdc - (amountPaidUsdc * tunnlTwitterOffers.getConfig().creatorFeePercentageBP) / 10000
        );
        assertEq(
            mockUsdcToken.balanceOf(creator3),
            amountPaidUsdc - (amountPaidUsdc * tunnlTwitterOffers.getConfig().creatorFeePercentageBP) / 10000
        );
        assertEq(
            mockUsdcToken.balanceOf(creator4),
            amountPaidUsdc - (amountPaidUsdc * tunnlTwitterOffers.getConfig().creatorFeePercentageBP) / 10000
        );
        // Assert total funds sent to the owner
        assertEq(mockUsdcToken.balanceOf(owner), totalFunds_sent_to_Owner);

        // Check no funds/dust left in the contract
        assertEq(mockUsdcToken.balanceOf(address(tunnlTwitterOffers)), 0);
    }

    function test_Verify_PayOut_Expir_Automation_Once() public {
        uint256 maxPaymentUsdc = 100e6;
        // offer needs payOut
        needs_PayOut();

         // offer needs Verification first and then expireAfter Failed Verification
        needs_Expiration();
        //warp time to capture expiration when perdormUpkeep is done
        vm.warp(block.timestamp + 100);

        // Ensure offer needs Verification
        needs_Verification();

        // Warp time to capture payoutDate
        uint offerDuration = 4 days;
        vm.warp(block.timestamp + offerDuration);

        //capture data to payOUt, Verify and Expire
        performUpkeep();

        // Fulfill Verification for OfferId(1)
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(1))],
            "",
            ""
        );

        // Retrieve the offer and assert its status is changed to "Active"
         ITunnlTwitterOffers.Offer memory offerVerify = getOffer(
            bytes32(uint256(1))
        );
        assertEq(uint256(offerVerify.status), uint256(ITunnlTwitterOffers.Status.Active));


          // Fulfill payout for OfferId(2)
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(2))],
            abi.encode(maxPaymentUsdc),
            ""
        );

        // Retrieve the offer and assert its status is changed to "Complete"
        ITunnlTwitterOffers.Offer memory offerPayOut = getOffer(bytes32(uint256(2)));
        assertEq(uint256(offerPayOut.status), uint256(ITunnlTwitterOffers.Status.Complete));

        // OfferId(3) Retrieve the offer and assert its status is changed to "Expired"
        ITunnlTwitterOffers.Offer memory offerExpire = getOffer(bytes32(uint256(3)));
        assertEq(
            uint256(offerExpire.status),
            uint256(ITunnlTwitterOffers.Status.Expired)
        );

        // Assert balances have been updated accordingly
        assertEq(mockUsdcToken.balanceOf(creator1), 0);
        //assert refund to advertiser3 for an expired offer
        assertEq(mockUsdcToken.balanceOf(advertiser3), 105e6);
        //assert balance still hold offerid(1) payment
        assertEq(mockUsdcToken.balanceOf(address(tunnlTwitterOffers)), 105e6);
        //assert creator2 get his payout
        assertEq(
            mockUsdcToken.balanceOf(creator2),
            uint256(100e6) - (uint256(100e6) * tunnlTwitterOffers.getConfig().creatorFeePercentageBP) / 10000
        );
    }
    ////// Internal functions //////////////

    function _giveFundsAndCreateOffer(uint256 maxPaymentUsdc, uint32 acceptanceDurationSeconds) private {
        // Total value which is equal to the maximum payment to the content creator plus all the fees
        uint maxValueUsdc = maxPaymentUsdc + ((uint256(maxPaymentUsdc) * uint256(tunnlTwitterOffers.getConfig().advertiserFeePercentageBP)) / 10000) + tunnlTwitterOffers.getConfig().flatFeeUsdc;
        // Create an offer as the advertiser
        vm.startPrank(advertiser);
        mockUsdcToken.mint(advertiser, maxValueUsdc);
        mockUsdcToken.approve(address(tunnlTwitterOffers), maxValueUsdc);
        tunnlTwitterOffers.createOffer(offerId, maxPaymentUsdc, acceptanceDurationSeconds, 4 days);
        vm.stopPrank();
    }

    function _giveFundsAndCreateOffers(ITunnlTwitterOffers.CreateOfferStruct[] memory offers) private {
        vm.assume(offers.length < 3);
        require(offers.length <= 4, "Test: Too many offers");
        uint256 totalMaxValueUsdc = 0;
        for(uint i = 0; i < offers.length; i++) {
            uint256 maxValueUsdc = offers[i].maxPaymentUsdc;
            maxValueUsdc += (maxValueUsdc * tunnlTwitterOffers.getConfig().advertiserFeePercentageBP) / 10000;
            maxValueUsdc += tunnlTwitterOffers.getConfig().flatFeeUsdc;
            // Check for overflow
            require(totalMaxValueUsdc + maxValueUsdc >= totalMaxValueUsdc, "Overflow in total value calculation");
            totalMaxValueUsdc += maxValueUsdc;
        }

        vm.startPrank(advertiser);
        mockUsdcToken.mint(advertiser, totalMaxValueUsdc);
        mockUsdcToken.approve(address(tunnlTwitterOffers), totalMaxValueUsdc);

        tunnlTwitterOffers.batchCreateOffers(offers);
        vm.stopPrank();
    }

    function CreateOffer_AcceptOffer_And_SubmitTweet(
        address _advertiser,
        address contentcreator,
        uint _id
    ) public {
        uint256 maxPaymentUsdc = 100e6;
        uint32 acceptanceDurationSeconds = 60 * 60 * 24 * 3;

        // Total value including fees
        uint maxValueUsdc = maxPaymentUsdc +
            ((uint256(maxPaymentUsdc) *
                uint256(tunnlTwitterOffers.getConfig().advertiserFeePercentageBP)) /
                10000
            ) + tunnlTwitterOffers.getConfig().flatFeeUsdc;

        // Create an offer as the advertiser
        vm.startPrank(_advertiser);
        mockUsdcToken.mint(_advertiser, maxValueUsdc);
        mockUsdcToken.approve(address(tunnlTwitterOffers), maxValueUsdc);
        tunnlTwitterOffers.createOffer(
            bytes32(_id),
            maxPaymentUsdc,
            acceptanceDurationSeconds,
            4 days
        );
        vm.stopPrank();

        // Accept the offer as the admin
        vm.startPrank(admin);
        tunnlTwitterOffers.acceptOffer(bytes32(_id), contentcreator);
         // Submit a tweet
        tunnlTwitterOffers.submitTweet(bytes32(_id), 100);
        vm.stopPrank();
    }

    function getOffer(bytes32 _offerId) internal view returns (ITunnlTwitterOffers.Offer memory) {
        // Call tunnlTwitterOffers.getOffers() with the offerId as the single element in the array
        bytes32[] memory _offerIds = new bytes32[](1);
        _offerIds[0] = _offerId;

         // Retrieve offers corresponding to the given IDs
        return tunnlTwitterOffers.getOffers(_offerIds)[0];
    }
    function performUpkeep() internal {
        // Check upkeep and get performData
         (, bytes memory performData) = tunnlTwitterOffers.checkUpkeep("");

         vm.recordLogs();
        // Perform upkeep with the retrieved data
        tunnlTwitterOffers.performUpkeep(performData);
        Vm.Log[] memory entries = vm.getRecordedLogs();

        for (uint i = 0; i < entries.length; i++) {
            if(entries[i].topics[0] == keccak256("RequestSent(bytes32,bytes32,uint8)")) {
                bytes32 eventOfferId = entries[i].topics[1];
                bytes32 functionsRequestId = entries[i].topics[2];
                functionsRequestIds[eventOfferId] = functionsRequestId;
            }
        }
    }

    function Create_Accept_Submit_Multple_Offer() internal{
        CreateOffer_AcceptOffer_And_SubmitTweet( advertiser1, creator1, 1);

        CreateOffer_AcceptOffer_And_SubmitTweet( advertiser2, creator2, 2);

        CreateOffer_AcceptOffer_And_SubmitTweet( advertiser3, creator3, 3);

        CreateOffer_AcceptOffer_And_SubmitTweet( advertiser4, creator4, 4);

        CreateOffer_AcceptOffer_And_SubmitTweet( advertiser5, creator5, 5);
    }

    function needs_Verification() internal{
        CreateOffer_AcceptOffer_And_SubmitTweet( advertiser1, creator1, 1);

        ITunnlTwitterOffers.Offer memory offer = getOffer(bytes32(uint256(1)));

        assertEq(uint256(offer.status), uint256(ITunnlTwitterOffers.Status.AwaitingVerification));
    }

    function needs_PayOut() internal{
        CreateOffer_AcceptOffer_And_SubmitTweet( advertiser2, creator2, 2);
        vm.warp(block.timestamp + 100);
        performUpkeep();
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[bytes32(uint256(2))],
            "",
            ""
        );
         ITunnlTwitterOffers.Offer memory offer = getOffer(
            bytes32(uint256(2))
        );

        assertEq(uint256(offer.status), uint256(ITunnlTwitterOffers.Status.Active));
    }

    function needs_Expiration() internal {
        uint256 maxPaymentUsdc = 100e6;
        uint32 acceptanceDurationSeconds = 60 * 60 * 24 * 3;
        bytes32 id3 = bytes32(uint256(3));
        uint maxValueUsdc = maxPaymentUsdc + ((uint256(maxPaymentUsdc) * uint256(tunnlTwitterOffers.getConfig().advertiserFeePercentageBP)) / 10000) + tunnlTwitterOffers.getConfig().flatFeeUsdc;

        vm.startPrank(advertiser3);
        mockUsdcToken.mint(advertiser3, maxValueUsdc);
        mockUsdcToken.approve(address(tunnlTwitterOffers), maxValueUsdc);
        tunnlTwitterOffers.createOffer(id3, maxPaymentUsdc, acceptanceDurationSeconds, 4 days);
        vm.stopPrank();

        vm.prank(admin);
        tunnlTwitterOffers.acceptOffer(id3, creator3);

        assertEq(uint(getOffer(id3).status), 1);
        assertEq(getOffer(id3).contentCreator, creator3);
    }

    function test_RetryFailedVerificationRequests() public {
        // Run a test to set up the initial conditions with a VerificationFail
        test_Verification_Fail();
        vm.warp(block.timestamp + 100); // Warp time to simulate the passage of the retry delay duration
        // Submit a tweet to put the offer back into a retryable state
        vm.startPrank(admin);
        tunnlTwitterOffers.submitTweet(offerId, 100);
        vm.stopPrank();
        // Get the current state of the offer and log it for debugging
        ITunnlTwitterOffers.Offer memory offer = getOffer(offerId);
        // Create a memory array for the offerIds and add the offerId to it
        bytes32[] memory _offerIds = new bytes32[](1);
        _offerIds[0] = offerId;

        // Retry the failed requests
        vm.prank(admin);
        tunnlTwitterOffers.retryRequests(_offerIds);

        // Verify the updated state of the offer after retrying
        offer = getOffer(offerId);
        assertEq(uint256(offer.status), uint256(ITunnlTwitterOffers.Status.VerificationInFlight));
    }

    function test_RetryFailedPayoutRequests() public {
        // Define the amount to be paid in USDC
        uint256 amountPaidUsdc = uint256(uint256(100e6));

        // Create an offer
        _giveFundsAndCreateOffer(amountPaidUsdc, 259200);
        // Accept the offer, submit a tweet, and simulate Chainlink automation for tweet verification
        vm.startPrank(admin);
        tunnlTwitterOffers.acceptOffer(offerId, contentCreator);
        tunnlTwitterOffers.submitTweet(offerId, 100);
        vm.stopPrank();

        // Warp time for tweet verification and perform Chainlink automation
        vm.warp(block.timestamp + 100);
        performUpkeep();

        // Fulfill request to verify tweet
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[offerId],
            "",
            ""
        );
        // Warp time for payout for verified tweets and perform Chainlink automation
        vm.warp(block.timestamp + (1 weeks - 100));
        performUpkeep();

        // Fulfill request with payout failure message
        mockFunctionsRouter.fulfill(
            address(tunnlTwitterOffers),
            functionsRequestIds[offerId],
            "",
            bytes("Failed to fetch valid secrets")
        );

        // Retrieve the offer and assert its status is changed to "PayoutFailed"
        ITunnlTwitterOffers.Offer memory offer = getOffer(
            offerId
        );
        assertEq(
            uint256(offer.status),
            uint256(ITunnlTwitterOffers.Status.PayoutFailed)
        );
        // Calculate the percentage fee
        uint percentaefee = (amountPaidUsdc * uint256(offer.advertiserFeePercentageBP)) /
                    10000;

        // Assert balances after payout failure
        assertEq(mockUsdcToken.balanceOf(advertiser), 0);

        assertEq(
            mockUsdcToken.balanceOf(address(tunnlTwitterOffers)),
            (amountPaidUsdc + percentaefee)
        );
        assertEq(mockUsdcToken.balanceOf(contentCreator), 0);

        // Create a memory array for the offerIds and add the offerId to it
        bytes32[] memory _offerIds = new bytes32[](1);
        _offerIds[0] = offerId;

        // Retry the failed requests
        vm.prank(admin);
        tunnlTwitterOffers.retryRequests(_offerIds);

        offer = getOffer(offerId);
        assertEq(uint256(offer.status), uint256(ITunnlTwitterOffers.Status.PayoutInFlight));
    }

    function test_setVerificationStatusWhenOfferIsNotActive() public {
        test_Verification_Fail();
        ITunnlTwitterOffers.Offer memory offerBefore = getOffer(offerId);
        assertEq(uint256(offerBefore.status), uint256(ITunnlTwitterOffers.Status.VerificationFailed));
        vm.prank(admin);
        tunnlTwitterOffers.setVerificationStatus(offerId, true);
        ITunnlTwitterOffers.Offer memory offerAfter = getOffer(offerId);
        assertEq(uint256(offerAfter.status), uint256(ITunnlTwitterOffers.Status.Active));
    }

    function test_setVerificationStatusWhenOfferIsActive() public {
        test_Verification_Success();
        ITunnlTwitterOffers.Offer memory offerBefore = getOffer(offerId);
        assertEq(uint256(offerBefore.status), uint256(ITunnlTwitterOffers.Status.Active));
        vm.prank(admin);
        tunnlTwitterOffers.setVerificationStatus(offerId, false);
        ITunnlTwitterOffers.Offer memory offerAfter = getOffer(offerId);
        assertEq(uint256(offerAfter.status), uint256(ITunnlTwitterOffers.Status.VerificationFailed));
    }

    function test_setVerificationStatusShouldRevertIfTimeExceedsPayout() public {
        test_Verification_Success();
        vm.warp(block.timestamp + 6 days); // a random date which exceeds payout date
        vm.prank(admin);
        vm.expectRevert("Expired");
        tunnlTwitterOffers.setVerificationStatus(offerId, false);
    }

    function test_setVerificationStatusShouldRevertIfOfferStatusIsPayoutInFlight() public {
        test_Verification_Success();
        vm.warp(block.timestamp + 4 days); // 1 day of submission + 3 days of post being live on X
        performUpkeep();
        ITunnlTwitterOffers.Offer memory offer = getOffer(offerId);
        assertEq(uint256(offer.status), uint256(ITunnlTwitterOffers.Status.PayoutInFlight));
        vm.prank(admin);
        vm.expectRevert("Expired");
        tunnlTwitterOffers.setVerificationStatus(offerId, true);
    }
    function test_setVerificationStatusShouldRevertIfMsgSenderIsNotAdmin() public {
        test_Verification_Fail();
        vm.prank(address(8));
        vm.expectRevert("Not admin");
        tunnlTwitterOffers.setVerificationStatus(offerId, true);
    }

    function test_setVerificationStatusShouldRevertIfOfferIsCompleted() public { // this test will automatically fail at the first timestamp check since payout has been done successfully
        test_PayOut();
        ITunnlTwitterOffers.Offer memory offer = getOffer(offerId);
        assertEq(uint256(offer.status), uint256(ITunnlTwitterOffers.Status.Complete));
        vm.prank(admin);
        vm.expectRevert("Expired");
        tunnlTwitterOffers.setVerificationStatus(offerId, true);
    }

    function test_PermitAndCreateOfferTogether() public {
        uint256 maxPaymentUsdc = 100e6;
        uint32 acceptanceDurationSeconds = 60 * 60 * 24 * 3;
        uint256 maxValueUsdc = maxPaymentUsdc + ((uint256(maxPaymentUsdc) * uint256(tunnlTwitterOffers.getConfig().advertiserFeePercentageBP)) / 10000) + tunnlTwitterOffers.getConfig().flatFeeUsdc;
        address brand = vm.addr(1); 
        // Mint tokens to brand
        vm.startPrank(brand);
        mockUsdcToken.mint(brand, maxValueUsdc);
        vm.stopPrank();

        // Fetching the DOMAIN_SEPARATOR and nonce not required for this test @audit

        // signing the permit here
        SigUtils.Permit memory permit = SigUtils.Permit({
                owner: brand,
                spender: address(tunnlTwitterOffers),
                value: maxValueUsdc,
                nonce: 0,
                deadline: 100 days
            });

            bytes32 structHash = keccak256(abi.encode(mockUsdcToken.PERMIT_TYPEHASH(), permit.owner, permit.spender, permit.value, permit.nonce, permit.deadline));
            bytes32 hash = mockUsdcToken.getHash(structHash);
            // bytes32 hash = _hashTypedDataV4(structHash);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash);

        // Call the permitAndCreateOffer function
        vm.startPrank(brand);
        tunnlTwitterOffers.createOfferWithPermit(
            offerId,
            brand,
            maxPaymentUsdc,
            acceptanceDurationSeconds,
            3 days,
            100 days,
            v,
            r,
            s
        );
        vm.stopPrank();
    }

    function test_BatchCreateOffers() public {
        // Arrange:
        ITunnlTwitterOffers.CreateOfferStruct[] memory createOfferStructs = new ITunnlTwitterOffers.CreateOfferStruct[](2);
        createOfferStructs[0] = ITunnlTwitterOffers.CreateOfferStruct({
            offerId: bytes32(uint256(1)),
            brand: advertiser,
            maxPaymentUsdc: 1000 * 10**6,  // USDC uses 6 decimals
            acceptanceDurationSeconds: 3 * 24 * 60 * 60,
            offerDurationSeconds: 4 days
        });

        createOfferStructs[1] = ITunnlTwitterOffers.CreateOfferStruct({
            offerId: bytes32(uint256(2)),
            brand: advertiser,
            maxPaymentUsdc: 2000 * 10**6,
            acceptanceDurationSeconds: 3 * 24 * 60 * 60,
            offerDurationSeconds: 4 days
        });

        // Act: Give funds to the advertiser and create offers
        _giveFundsAndCreateOffers(createOfferStructs);

        // Assert: Verify the state of the first offer
        ITunnlTwitterOffers.Offer memory offer1 = getOffer(offerIds[0]);
        assertEq(offer1.creationDate, block.timestamp);
        assertEq(offer1.acceptanceExpirationDate, block.timestamp + createOfferStructs[0].acceptanceDurationSeconds);
        assertEq(offer1.advertiser, advertiser);
        assertEq(offer1.maxValueUsdc, 1000 * 10**6 + (1000 * 1e6 * uint256(tunnlTwitterOffers.getConfig().advertiserFeePercentageBP) / 10000) + tunnlTwitterOffers.getConfig().flatFeeUsdc);
        assertEq(uint256(offer1.status), 0);

        // Assert: Verify the state of the second offer
        ITunnlTwitterOffers.Offer memory offer2 = getOffer(offerIds[1]);
        assertEq(offer2.creationDate, block.timestamp);
        assertEq(offer2.acceptanceExpirationDate, block.timestamp + createOfferStructs[1].acceptanceDurationSeconds);
        assertEq(offer2.advertiser, advertiser);
        assertEq(offer2.maxValueUsdc, 2000 * 10**6 + (2000 * 1e6 * uint256(tunnlTwitterOffers.getConfig().advertiserFeePercentageBP) / 10000) + tunnlTwitterOffers.getConfig().flatFeeUsdc);
        assertEq(uint256(offer2.status), 0);
    }
}