// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LiunPool} from "../src/LiunPool.sol";

contract LiunPoolTest is Test {
    LiunPool pool;

    // Anti-spam publish deposit and per-publish gas refund.
    uint256 constant PUBLISH_DEPOSIT = 0.01 ether;
    uint256 constant GAS_REFUND      = 0.001 ether;

    bytes nodeId = hex"aa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cc";
    address payable payoutAddr = payable(address(0xBEEF));

    address publisher  = address(0xABCD);
    address challenger = address(0x1234);

    function setUp() public {
        pool = new LiunPool(PUBLISH_DEPOSIT, GAS_REFUND);
        vm.deal(address(this),  1_000 ether);
        vm.deal(publisher,      10 ether);
        vm.deal(challenger,     10 ether);
        pool.deposit{value: 100 ether}();
    }

    receive() external payable {}

    // ---- helpers ------------------------------------------------------

    function _leaf(bytes memory id, address payout, uint256 amount)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encode(id, payout, amount));
    }

    // ---- happy path ---------------------------------------------------

    function test_happyPath_anyoneCanPublishAndClaim() public {
        // Tally's per-node amounts are already net-of-gas-refund —
        // the off-chain tally subtracts GAS_REFUND from the epoch
        // budget before splitting. So the Merkle leaf commits to the
        // final claim amount, and the epoch budget = leaves + refund.
        uint256 epoch = 1;
        uint256 claimAmount = 1 ether;
        uint256 budget = claimAmount + GAS_REFUND;
        bytes32 root = _leaf(nodeId, payoutAddr, claimAmount);

        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, budget);

        // Inside challenge window — claim should fail.
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(LiunPool.StillInChallengeWindow.selector);
        pool.claim(epoch, nodeId, payoutAddr, claimAmount, proof);

        vm.warp(block.timestamp + 7 days + 1);

        uint256 pubBefore = publisher.balance;
        uint256 before = payoutAddr.balance;
        pool.claim(epoch, nodeId, payoutAddr, claimAmount, proof);

        // Publisher got deposit + gas refund.
        assertEq(publisher.balance - pubBefore, PUBLISH_DEPOSIT + GAS_REFUND);
        assertEq(payoutAddr.balance - before, claimAmount);
    }

    // ---- anti-spam ----------------------------------------------------

    function test_publishRequiresDeposit() public {
        uint256 epoch = 2;
        bytes32 root = _leaf(nodeId, payoutAddr, 1 ether);
        vm.prank(publisher);
        vm.expectRevert(LiunPool.InsufficientDeposit.selector);
        pool.postEpoch{value: PUBLISH_DEPOSIT - 1}(epoch, root, 1 ether);
    }

    function test_doublePostRejected() public {
        uint256 epoch = 3;
        bytes32 root = _leaf(nodeId, payoutAddr, 0.1 ether);
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, 0.1 ether);
        vm.prank(publisher);
        vm.expectRevert(LiunPool.EpochAlreadyPosted.selector);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, 0.1 ether);
    }

    function test_overBudgetRejected() public {
        uint256 epoch = 4;
        uint256 tooMuch = 10_000 ether;
        bytes32 root = _leaf(nodeId, payoutAddr, tooMuch);
        vm.prank(publisher);
        vm.expectRevert(LiunPool.UnderFunded.selector);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, tooMuch);
    }

    // ---- challenge / invalidation ------------------------------------

    function test_challenge_slashesPublisherDeposit() public {
        uint256 epoch = 5;
        uint256 amount = 0.5 ether;
        bytes32 root = _leaf(nodeId, payoutAddr, amount);
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, amount);

        bytes32 altRoot = bytes32(uint256(root) ^ 1);
        uint256 challengerBefore = challenger.balance;
        vm.prank(challenger);
        pool.invalidateEpoch(epoch, altRoot);

        // Challenger got half the deposit.
        assertEq(challenger.balance - challengerBefore, PUBLISH_DEPOSIT / 2);

        // After the window, claim must fail because invalidated.
        vm.warp(block.timestamp + 7 days + 1);
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(LiunPool.Invalidated.selector);
        pool.claim(epoch, nodeId, payoutAddr, amount, proof);
    }

    function test_cannotChallengeWithSameRoot() public {
        uint256 epoch = 6;
        bytes32 root = _leaf(nodeId, payoutAddr, 0.1 ether);
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, 0.1 ether);
        vm.prank(challenger);
        vm.expectRevert(LiunPool.DifferentRootRequired.selector);
        pool.invalidateEpoch(epoch, root);
    }

    function test_cannotChallengeAfterWindow() public {
        uint256 epoch = 7;
        bytes32 root = _leaf(nodeId, payoutAddr, 0.1 ether);
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, 0.1 ether);
        vm.warp(block.timestamp + 7 days + 1);
        bytes32 altRoot = bytes32(uint256(root) ^ 1);
        vm.prank(challenger);
        vm.expectRevert(LiunPool.StillInChallengeWindow.selector);
        pool.invalidateEpoch(epoch, altRoot);
    }

    // ---- finalize + gas refund ---------------------------------------

    function test_finalize_returnsDepositAndRefund() public {
        uint256 epoch = 8;
        uint256 amount = 0.5 ether;
        bytes32 root = _leaf(nodeId, payoutAddr, amount);
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, amount);

        vm.warp(block.timestamp + 7 days + 1);
        uint256 before = publisher.balance;
        pool.finalizeEpoch(epoch);
        assertEq(publisher.balance - before, PUBLISH_DEPOSIT + GAS_REFUND);
    }

    function test_cannotFinalizeEarly() public {
        uint256 epoch = 9;
        bytes32 root = _leaf(nodeId, payoutAddr, 0.1 ether);
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, 0.1 ether);
        vm.expectRevert(LiunPool.StillInChallengeWindow.selector);
        pool.finalizeEpoch(epoch);
    }

    function test_cannotFinalizeInvalidated() public {
        uint256 epoch = 10;
        bytes32 root = _leaf(nodeId, payoutAddr, 0.1 ether);
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, 0.1 ether);
        bytes32 altRoot = bytes32(uint256(root) ^ 1);
        vm.prank(challenger);
        pool.invalidateEpoch(epoch, altRoot);
        vm.warp(block.timestamp + 7 days + 1);
        vm.expectRevert(LiunPool.Invalidated.selector);
        pool.finalizeEpoch(epoch);
    }

    // ---- merkle proof w/ multiple leaves ------------------------------

    function test_multiLeafProof() public {
        uint256 epoch = 11;
        uint256 amt1 = 0.1 ether;
        uint256 amt2 = 0.2 ether;
        address payable payout2 = payable(address(0xCAFE));
        bytes memory node2 = hex"bb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dd";

        // Amounts already net of gas refund for this test's simplicity.
        bytes32 leaf1 = _leaf(nodeId, payoutAddr, amt1);
        bytes32 leaf2 = _leaf(node2, payout2, amt2);

        bytes32 root;
        if (leaf1 < leaf2) root = keccak256(abi.encodePacked(leaf1, leaf2));
        else               root = keccak256(abi.encodePacked(leaf2, leaf1));

        uint256 budget = amt1 + amt2 + GAS_REFUND;
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, budget);
        vm.warp(block.timestamp + 7 days + 1);

        bytes32[] memory proof1 = new bytes32[](1);
        proof1[0] = leaf2;
        bytes32[] memory proof2 = new bytes32[](1);
        proof2[0] = leaf1;

        pool.claim(epoch, nodeId, payoutAddr, amt1, proof1);
        pool.claim(epoch, node2, payout2, amt2, proof2);
        assertEq(payoutAddr.balance, amt1);
        assertEq(payout2.balance,    amt2);
    }

    function test_rejectsWrongProof() public {
        uint256 epoch = 12;
        uint256 amount = 0.1 ether;
        bytes32 root = _leaf(nodeId, payoutAddr, amount);
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, amount + GAS_REFUND);
        vm.warp(block.timestamp + 7 days + 1);
        bytes32[] memory bogus = new bytes32[](1);
        bogus[0] = bytes32(uint256(123));
        vm.expectRevert(LiunPool.BadMerkleProof.selector);
        pool.claim(epoch, nodeId, payoutAddr, amount, bogus);
    }

    // ---- deposits ------------------------------------------------------

    function test_depositIncrementsBalance() public {
        uint256 before = address(pool).balance;
        pool.deposit{value: 50 ether}();
        assertEq(address(pool).balance - before, 50 ether);
    }

    function test_plainSendCountsAsDeposit() public {
        uint256 before = address(pool).balance;
        (bool ok, ) = address(pool).call{value: 25 ether}("");
        assertTrue(ok);
        assertEq(address(pool).balance - before, 25 ether);
    }

    function test_zeroDepositRejected() public {
        vm.expectRevert("zero deposit");
        pool.deposit{value: 0}();
    }

    function test_alreadyClaimedBlocksDouble() public {
        uint256 epoch = 13;
        uint256 amount = 0.1 ether;
        bytes32 root = _leaf(nodeId, payoutAddr, amount);
        vm.prank(publisher);
        pool.postEpoch{value: PUBLISH_DEPOSIT}(epoch, root, amount + GAS_REFUND);
        vm.warp(block.timestamp + 7 days + 1);
        bytes32[] memory proof = new bytes32[](0);
        pool.claim(epoch, nodeId, payoutAddr, amount, proof);
        vm.expectRevert(LiunPool.AlreadyClaimed.selector);
        pool.claim(epoch, nodeId, payoutAddr, amount, proof);
    }
}
