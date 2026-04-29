pub mod topic {
    pub const TRANSACTIONS: &str = "transactions";
    pub const BLOCKS: &str = "blocks";
}

// use decay to tackle byzantine
// use 0.0..1.0 score
// reward() / penalize_invalid() / penalize_duplicate()
// blacklist when hits 0 for example (BLACKLIST_THRESHOLD)
// define INIT_SCORE, MAX_SCORE, BLACKLIST_THRESHOLD, REWARD_VALID, PENALTY_INVALID, PENALTY_DUPLICATE
// topic score -> score / valid_count / invalid_cont / duplicate_count
// peer trust -> topics (string / topic_score) / blacklisted (bool)
// aggregate_score() / check_blacklist() / decay()
// TrustTable -> hash map with <PeerID, PeerTrust>
// handy functs blacklist_peers() is_blacklist()
// and single functs for specific peer so *API*
