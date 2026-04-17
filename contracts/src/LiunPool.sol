// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title LiunPool
/// @notice Public-goods funding pool for the Liun network. Denominated in ETH.
///
/// Anyone deposits ETH. Anyone publishes an epoch's payout root. Nodes
/// claim. No roles, no committee. The UX is: run `liun-node`, serve
/// traffic, collect ETH — you won't know whether you were the one who
/// happened to publish the week's tally.
///
/// ## Unified-node model
///
/// The earlier design had a privileged "committee" publish epochs with
/// k-of-N ECDSA. This contract drops that. The tally is a
/// **deterministic pure function** of the public blob receipts + the
/// public trust graph — anyone with internet access can re-run it and
/// get the same Merkle root. So:
///
///   1. The first node whose publish-timer fires each epoch submits
///      its computed root. It pays gas.
///   2. A **publish deposit** (refunded after 7-day challenge window
///      closes with no invalidation) prevents spam submissions.
///   3. Publisher's gas cost is **refunded from the epoch budget** before
///      per-node payouts, so publishing is net-zero.
///   4. Anyone who thinks the root is wrong submits an
///      `invalidateEpoch` within 7 days; must re-derive a different root
///      on chain. Successful challenge slashes the publisher's deposit to
///      the challenger.
///
/// What stays the same:
///   * Deposits are open: `deposit()` payable, or plain ETH send.
///   * Merkle proof claim after challenge window.
///   * Challenge window = 7 days.
contract LiunPool {
    /// Minimum ETH deposit a publisher must attach to postEpoch.
    /// Returned to them after the challenge window closes without
    /// invalidation. Rough sizing: 10x expected gas cost, so small
    /// enough to not deter honest publishers, large enough that a
    /// spammer eats a real loss per bogus post.
    uint256 public immutable publishDepositWei;

    /// Estimated gas refund per successful publish, taken off the top of
    /// the budget before per-node distribution. The publisher receives
    /// this much ETH on successful finalization.
    uint256 public immutable gasRefundWei;

    uint256 public constant CHALLENGE_WINDOW = 7 days;

    struct Epoch {
        bytes32 root;
        uint256 budgetWei;
        uint256 postedAt;
        address publisher;
        uint256 publisherDeposit;
        bool    invalidated;
        bool    finalized; // deposit returned / gas paid
    }
    mapping(uint256 => Epoch) public epochs;
    mapping(uint256 => mapping(bytes32 => bool)) public claimed;

    event Deposited(address indexed from, uint256 amount);
    event EpochPosted(uint256 indexed epoch, bytes32 root, uint256 budgetWei,
                      address indexed publisher);
    event EpochInvalidated(uint256 indexed epoch, address indexed challenger);
    event EpochFinalized(uint256 indexed epoch, address indexed publisher,
                         uint256 gasRefund, uint256 depositReturned);
    event Claimed(uint256 indexed epoch, bytes32 indexed nodeId,
                  address payout, uint256 amount);

    error EpochAlreadyPosted();
    error EpochMissing();
    error StillInChallengeWindow();
    error AlreadyClaimed();
    error AlreadyFinalized();
    error BadMerkleProof();
    error UnderFunded();
    error Invalidated();
    error InsufficientDeposit();
    error DifferentRootRequired();
    error TransferFailed();

    constructor(uint256 _publishDepositWei, uint256 _gasRefundWei) {
        publishDepositWei = _publishDepositWei;
        gasRefundWei = _gasRefundWei;
    }

    // ---- deposit ------------------------------------------------------

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        emit Deposited(msg.sender, msg.value);
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    // ---- publish ------------------------------------------------------

    /// Anyone may publish. `msg.value` must be at least
    /// `publishDepositWei` — held until finalization or invalidation.
    function postEpoch(
        uint256 epoch,
        bytes32 root,
        uint256 budgetWei
    ) external payable {
        if (msg.value < publishDepositWei) revert InsufficientDeposit();
        if (epochs[epoch].root != bytes32(0)) revert EpochAlreadyPosted();
        if (budgetWei > address(this).balance - msg.value)
            revert UnderFunded();

        epochs[epoch] = Epoch({
            root: root,
            budgetWei: budgetWei,
            postedAt: block.timestamp,
            publisher: msg.sender,
            publisherDeposit: msg.value,
            invalidated: false,
            finalized: false
        });
        emit EpochPosted(epoch, root, budgetWei, msg.sender);
    }

    // ---- challenge ----------------------------------------------------

    /// Challenge an epoch with a DIFFERENT root re-derived from the same
    /// inputs. The challenger must submit their own computed root that
    /// disagrees with the posted one; both roots are functions of the
    /// same public inputs, so disagreement is proof somebody computed
    /// wrong. Without access to the raw inputs on-chain, the contract
    /// can't decide WHICH is right — so:
    ///
    ///   v1 (this): any disagreement within the challenge window
    ///   invalidates the epoch (no payouts). Publisher's deposit is
    ///   split: half to the challenger, half burned. No epoch means no
    ///   payouts that week — real operators will re-run, resolve the
    ///   disagreement off-chain, and repost for the next epoch number.
    ///
    ///   v2 (future): submit blob hashes + the trust-graph hash
    ///   on-chain; include a fraud-proof witness of a specific leaf
    ///   that differs. Contract can then decide which root is wrong.
    function invalidateEpoch(uint256 epoch, bytes32 alternativeRoot) external {
        Epoch storage e = epochs[epoch];
        if (e.root == bytes32(0)) revert EpochMissing();
        if (e.invalidated) revert Invalidated();
        if (e.finalized) revert AlreadyFinalized();
        if (block.timestamp >= e.postedAt + CHALLENGE_WINDOW) {
            revert StillInChallengeWindow();
        }
        if (alternativeRoot == e.root) revert DifferentRootRequired();

        e.invalidated = true;

        // Split the publisher's deposit: half to challenger, half burned.
        uint256 half = e.publisherDeposit / 2;
        uint256 toChallenger = half;
        uint256 toBurn = e.publisherDeposit - half;
        e.publisherDeposit = 0;

        // Burn = keep in contract (accrues to future budgets).
        // Challenger gets their half now.
        (bool ok, ) = msg.sender.call{value: toChallenger}("");
        if (!ok) revert TransferFailed();
        emit EpochInvalidated(epoch, msg.sender);
        // toBurn stays in the contract, accruing to future epochs.
        (toBurn);
    }

    /// After the challenge window closes on an uncontested epoch,
    /// return the publisher's deposit + pay them the gas refund.
    /// Callable by anyone (convenience — publisher doesn't have to
    /// come back to collect, a subsequent `claim` call can do it).
    function finalizeEpoch(uint256 epoch) public {
        Epoch storage e = epochs[epoch];
        if (e.root == bytes32(0)) revert EpochMissing();
        if (e.invalidated) revert Invalidated();
        if (e.finalized) revert AlreadyFinalized();
        if (block.timestamp < e.postedAt + CHALLENGE_WINDOW) {
            revert StillInChallengeWindow();
        }
        e.finalized = true;
        uint256 deposit = e.publisherDeposit;
        e.publisherDeposit = 0;
        uint256 refund = gasRefundWei;
        if (refund > e.budgetWei) refund = e.budgetWei;
        e.budgetWei -= refund;

        uint256 total = deposit + refund;
        (bool ok, ) = e.publisher.call{value: total}("");
        if (!ok) revert TransferFailed();
        emit EpochFinalized(epoch, e.publisher, refund, deposit);
    }

    // ---- claim --------------------------------------------------------

    function claim(
        uint256 epoch,
        bytes calldata nodeId, // 48 bytes
        address payout,
        uint256 amount,
        bytes32[] calldata proof
    ) external {
        Epoch storage e = epochs[epoch];
        if (e.root == bytes32(0)) revert EpochMissing();
        if (e.invalidated) revert Invalidated();
        if (block.timestamp < e.postedAt + CHALLENGE_WINDOW) {
            revert StillInChallengeWindow();
        }
        require(nodeId.length == 48, "nodeId length");

        // Lazy-finalize on first claim so the publisher's deposit
        // returns without requiring a separate call.
        if (!e.finalized) {
            finalizeEpoch(epoch);
        }

        bytes32 leaf = keccak256(abi.encode(nodeId, payout, amount));
        if (claimed[epoch][leaf]) revert AlreadyClaimed();

        if (!_verifyMerkle(proof, e.root, leaf)) revert BadMerkleProof();

        claimed[epoch][leaf] = true;
        (bool ok, ) = payout.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Claimed(epoch, bytes32(nodeId[0:32]), payout, amount);
    }

    // ---- helpers ------------------------------------------------------

    function _verifyMerkle(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i; i < proof.length; ++i) {
            h = _hashPair(h, proof[i]);
        }
        return h == root;
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b
            ? keccak256(abi.encodePacked(a, b))
            : keccak256(abi.encodePacked(b, a));
    }
}
