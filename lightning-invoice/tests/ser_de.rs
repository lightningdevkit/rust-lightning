extern crate bech32;
extern crate bitcoin_hashes;
extern crate lightning;
extern crate lightning_invoice;
extern crate secp256k1;
extern crate hex;

use bitcoin_hashes::hex::FromHex;
use bitcoin_hashes::{sha256, Hash};
use bech32::u5;
use lightning::ln::PaymentSecret;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning_invoice::*;
use secp256k1::PublicKey;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use std::collections::HashSet;
use std::time::Duration;
use std::str::FromStr;

fn get_test_tuples() -> Vec<(String, SignedRawInvoice, bool, bool)> {
	vec![
		(
			"lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
						"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.description("Please consider supporting this project".to_owned())
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d81127425e434ca29929406c23bba1ae8ac6ca32880b38d4bf6ff874024cac34ba9625f1").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(250_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.description("1 cup coffee".to_owned())
				.expiry_time(Duration::from_secs(60))
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("e59e3ffbd3945e4334879158d31e89b076dff54f3fa7979ae79df2db9dcaf5896cbfe1a478b8d2307e92c88139464cb7e6ef26e414c4abe33337961ddc5e8ab1").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(250_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.description("ナンセンス 1杯".to_owned())
				.expiry_time(Duration::from_secs(60))
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("bae41ef385e0fc972977c7ea42b12cbd76577d2412919da8a8a22f9577b6507710c0e96dd78c821dea16453037f717f44aa7e3d196ebb18fbb97307dcb7336c3").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(2_000_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.description_hash(sha256::Hash::hash(b"One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon"))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("f67a5f696648fa4fb102e1a07b230e54722f8e024cee71e80b4847ac191da3fb2d2cdb28cc32344d7e9a9cf5c9b6a0ee0582ae46e9938b9c81e344a4dbb5289d").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8".to_owned(),
			InvoiceBuilder::new(Currency::BitcoinTestnet)
				.amount_milli_satoshis(2_000_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.description_hash(sha256::Hash::hash(b"One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon"))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.fallback(Fallback::PubKeyHash([49, 114, 181, 101, 79, 102, 131, 200, 251, 20, 105, 89, 211, 71, 206, 48, 60, 174, 76, 167]))
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("6ca95a74dc32e69ced6175b15a5cc56a92bf19f5dace0f134b7d94d464b9f5cf6090a18d48b243f289394d17bdf89466d8e6b37df5981f696bc3dd5986e1bee1").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(2_000_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.description_hash(sha256::Hash::hash(b"One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon"))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.fallback(Fallback::PubKeyHash([4, 182, 31, 125, 193, 234, 13, 201, 148, 36, 70, 76, 196, 6, 77, 197, 100, 217, 30, 137]))
				.private_route(RouteHint(vec![RouteHintHop {
					src_node_id: PublicKey::from_slice(&hex::decode(
							"029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"
						).unwrap()).unwrap(),
					short_channel_id: (66051 << 40) | (263430 << 16) | 1800,
					fees: RoutingFees { base_msat: 1, proportional_millionths: 20 },
					cltv_expiry_delta: 3,
					htlc_maximum_msat: None, htlc_minimum_msat: None,
				}, RouteHintHop {
					src_node_id: PublicKey::from_slice(&hex::decode(
							"039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"
						).unwrap()).unwrap(),
					short_channel_id: (197637 << 40) | (395016 << 16) | 2314,
					fees: RoutingFees { base_msat: 2, proportional_millionths: 30 },
					cltv_expiry_delta: 4,
					htlc_maximum_msat: None, htlc_minimum_msat: None,
				}]))
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("6a6586db4e8f6d40e3a5bb92e4df5110c627e9ce493af237e20a046b4e86ea200178c59564ecf892f33a9558bf041b6ad2cb8292d7a6c351fbb7f2ae2d16b54e").unwrap(),
						RecoveryId::from_i32(0).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z99qrsgqz6qsgww34xlatfj6e3sngrwfy3ytkt29d2qttr8qz2mnedfqysuqypgqex4haa2h8fx3wnypranf3pdwyluftwe680jjcfp438u82xqphf75ym".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(2_000_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.description_hash(sha256::Hash::hash(b"One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon"))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.fallback(Fallback::ScriptHash([143, 85, 86, 59, 154, 25, 243, 33, 194, 17, 233, 185, 243, 140, 223, 104, 110, 160, 120, 69]))
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("16810439d1a9bfd5a65acc61340dc92448bb2d456a80b58ce012b73cb5202438020500c9ab7ef5573a4d174c811f669885ae27f895bb3a3be52c243589f87518").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7k9qrsgqt29a0wturnys2hhxpner2e3plp6jyj8qx7548zr2z7ptgjjc7hljm98xhjym0dg52sdrvqamxdezkmqg4gdrvwwnf0kv2jdfnl4xatsqmrnsse".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(2_000_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.description_hash(sha256::Hash::hash(b"One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon"))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.fallback(Fallback::SegWitProgram { version: u5::try_from_u8(0).unwrap(),
					program: vec![117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214]
				})
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("5a8bd7b97c1cc9055ee60cf2356621f8752248e037a953886a1782b44a58f5ff2d94e6bc89b7b514541a3603bb33722b6c08aa1a3639d34becc549a99fea6eae").unwrap(),
						RecoveryId::from_i32(0).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(2_000_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.description_hash(sha256::Hash::hash(b"One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon"))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.fallback(Fallback::SegWitProgram { version: u5::try_from_u8(0).unwrap(),
					program: vec![24, 99, 20, 60, 20, 197, 22, 104, 4, 189, 25, 32, 51, 86, 218, 19, 108, 152, 86, 120, 205, 77, 39, 161, 184, 198, 50, 150, 4, 144, 50, 98]
				})
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("2b3ec248f80301a421817369194f012cdd8af8df1c279981420f9e901e20fa3309d791e11355e609b59ce4a220852a0cd55ab862b1785a83b206c90fa74d01c8").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(967878534)
				.duration_since_epoch(Duration::from_secs(1572468703))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f"
				).unwrap())
				.expiry_time(Duration::from_secs(604800))
				.min_final_cltv_expiry_delta(10)
				.description("Blockstream Store: 88.85 USD for Blockstream Ledger Nano S x 1, \"Back In My Day\" Sticker x 2, \"I Got Lightning Working\" Sticker x 2 and 1 more items".to_owned())
				.private_route(RouteHint(vec![RouteHintHop {
					src_node_id: PublicKey::from_slice(&hex::decode(
							"03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7"
						).unwrap()).unwrap(),
					short_channel_id: (589390 << 40) | (3312 << 16) | 1,
					fees: RoutingFees { base_msat: 1000, proportional_millionths: 2500 },
					cltv_expiry_delta: 40,
					htlc_maximum_msat: None, htlc_minimum_msat: None,
				}]))
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("1b1160cf6186b55722c1ac7ea502086baaccaabdc76b326e666b7f309d972b15069bfca11cd365304b36f48230cc12f3f13a017aab65f7c165a169df32282a58").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			false, // Same features as set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpz3uapa".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(2_500_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.description("coffee beans".to_owned())
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("5755469bf4b8e6b6ae7a1308d5f9bad5c82812e0855cd24fac242aa323fa820c5c551ede4faeabcb7fb6d5a464ad0e35c86f615589ee0e0c250c216a662198c1").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			true, // Different features than set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"LNBC25M1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5VDHKVEN9V5SXYETPDEESSP5ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYGS9Q5SQQQQQQQQQQQQQQQQSGQ2A25DXL5HRNTDTN6ZVYDT7D66HYZSYHQS4WDYNAVYS42XGL6SGX9C4G7ME86A27T07MDTFRY458RTJR0V92CNMSWPSJSCGT2VCSE3SGPZ3UAPA".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(2_500_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.description("coffee beans".to_owned())
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("5755469bf4b8e6b6ae7a1308d5f9bad5c82812e0855cd24fac242aa323fa820c5c551ede4faeabcb7fb6d5a464ad0e35c86f615589ee0e0c250c216a662198c1").unwrap(),
						RecoveryId::from_i32(1).unwrap()
					)
				}).unwrap(),
			true, // Different features than set in InvoiceBuilder
			false, // No unknown fields
		),
		(
			"lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2qrqqqfppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhpnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqspnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnpkqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz599y53s3ujmcfjp5xrdap68qxymkqphwsexhmhr8wdz5usdzkzrse33chw6dlp3jhuhge9ley7j2ayx36kawe7kmgg8sv5ugdyusdcqzn8z9x".to_owned(),
			InvoiceBuilder::new(Currency::Bitcoin)
				.amount_milli_satoshis(2_500_000_000)
				.duration_since_epoch(Duration::from_secs(1496314658))
				.payment_secret(PaymentSecret([0x11; 32]))
				.payment_hash(sha256::Hash::from_hex(
					"0001020304050607080900010203040506070809000102030405060708090102"
				).unwrap())
				.description("coffee beans".to_owned())
				.build_raw()
				.unwrap()
				.sign(|_| {
					RecoverableSignature::from_compact(
						&hex::decode("150a5252308f25bc2641a186de87470189bb003774326beee33b9a2a720d1584386631c5dda6fc3195f97464bfc93d2574868eadd767d6da1078329c4349c837").unwrap(),
						RecoveryId::from_i32(0).unwrap()
					)
				}).unwrap(),
			true, // Different features than set in InvoiceBuilder
			true, // Some unknown fields
		),
	]
}

#[test]
fn invoice_deserialize() {
	for (serialized, deserialized, ignore_feature_diff, ignore_unknown_fields) in get_test_tuples() {
		eprintln!("Testing invoice {}...", serialized);
		let parsed = serialized.parse::<SignedRawInvoice>().unwrap();

		let (parsed_invoice, _, parsed_sig) = parsed.into_parts();
		let (deserialized_invoice, _, deserialized_sig) = deserialized.into_parts();

		assert_eq!(deserialized_sig, parsed_sig);
		assert_eq!(deserialized_invoice.hrp, parsed_invoice.hrp);
		assert_eq!(deserialized_invoice.data.timestamp, parsed_invoice.data.timestamp);

		let mut deserialized_hunks: HashSet<_> = deserialized_invoice.data.tagged_fields.iter().collect();
		let mut parsed_hunks: HashSet<_> = parsed_invoice.data.tagged_fields.iter().collect();
		if ignore_feature_diff {
			deserialized_hunks.retain(|h|
				if let RawTaggedField::KnownSemantics(TaggedField::Features(_)) = h { false } else { true });
			parsed_hunks.retain(|h|
				if let RawTaggedField::KnownSemantics(TaggedField::Features(_)) = h { false } else { true });
		}
		if ignore_unknown_fields {
			parsed_hunks.retain(|h|
				if let RawTaggedField::UnknownSemantics(_) = h { false } else { true });
		}
		assert_eq!(deserialized_hunks, parsed_hunks);

		Invoice::from_signed(serialized.parse::<SignedRawInvoice>().unwrap()).unwrap();
	}
}

#[test]
fn test_bolt_invalid_invoices() {
	// Tests the BOLT 11 invalid invoice test vectors
	assert_eq!(Invoice::from_str(
		"lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q4psqqqqqqqqqqqqqqqqsgqtqyx5vggfcsll4wu246hz02kp85x4katwsk9639we5n5yngc3yhqkm35jnjw4len8vrnqnf5ejh0mzj9n3vz2px97evektfm2l6wqccp3y7372"
		), Err(ParseOrSemanticError::SemanticError(SemanticError::InvalidFeatures)));
	assert_eq!(Invoice::from_str(
		"lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt"
		), Err(ParseOrSemanticError::ParseError(ParseError::Bech32Error(bech32::Error::InvalidChecksum))));
	assert_eq!(Invoice::from_str(
		"pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny"
		), Err(ParseOrSemanticError::ParseError(ParseError::Bech32Error(bech32::Error::MissingSeparator))));
	assert_eq!(Invoice::from_str(
		"LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny"
		), Err(ParseOrSemanticError::ParseError(ParseError::Bech32Error(bech32::Error::MixedCase))));
	assert_eq!(Invoice::from_str(
		"lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqwgt7mcn5yqw3yx0w94pswkpq6j9uh6xfqqqtsk4tnarugeektd4hg5975x9am52rz4qskukxdmjemg92vvqz8nvmsye63r5ykel43pgz7zq0g2"
		), Err(ParseOrSemanticError::SemanticError(SemanticError::InvalidSignature)));
	assert_eq!(Invoice::from_str(
		"lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh"
		), Err(ParseOrSemanticError::ParseError(ParseError::TooShortDataPart)));
	assert_eq!(Invoice::from_str(
		"lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqrrzc4cvfue4zp3hggxp47ag7xnrlr8vgcmkjxk3j5jqethnumgkpqp23z9jclu3v0a7e0aruz366e9wqdykw6dxhdzcjjhldxq0w6wgqcnu43j"
		), Err(ParseOrSemanticError::ParseError(ParseError::UnknownSiPrefix)));
	assert_eq!(Invoice::from_str(
		"lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk32uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp99202x"
		), Err(ParseOrSemanticError::SemanticError(SemanticError::ImpreciseAmount)));
}
