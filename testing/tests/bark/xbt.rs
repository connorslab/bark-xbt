//! Private activated-XBT lifecycle; deterministic regtest coins only.
use bitcoin::Amount;
use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::exit::complete_exit;

#[tokio::test]
async fn xbt_lifecycle() {
	let ctx = TestContext::new("xbt/lifecycle").await;
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).create().await;
	let alice = ctx.bark("alice", &srv).funded(sat(1_000_000)).create().await;
	let bob = ctx.bark("bob", &srv).create().await;

	alice.board_and_confirm_and_register(&ctx, sat(500_000)).await;
	assert_eq!(alice.spendable_balance().await, sat(500_000));
	ctx.refresh_all(&srv, &[&alice]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	alice.send_oor(&bob.address().await, sat(100_000)).await;
	assert_eq!(bob.spendable_balance().await, sat(100_000));

	bob.offboard_all(&bob.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	assert_eq!(bob.spendable_balance().await, Amount::ZERO);
	assert!(bob.onchain_balance().await > sat(90_000));
	assert!(bob.onchain_balance().await < sat(100_000));

	// The client must recover its remaining funds without the operator.
	srv.stop().await.unwrap();
	let before = alice.onchain_balance().await;
	alice.start_exit_all().await;
	complete_exit(&ctx, &alice).await;
	alice.claim_all_exits(alice.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	let recovered = alice.onchain_balance().await;
	assert!(recovered > before + sat(300_000), "exit lost more than the test fee budget");
	assert!(recovered < before + sat(400_000), "exit must pay transaction fees");
}
