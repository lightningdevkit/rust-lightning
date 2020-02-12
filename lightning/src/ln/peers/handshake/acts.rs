pub struct ActOne(
	pub(super) [u8; 50]
);

pub struct ActTwo(
	pub(super) [u8; 50]
);

pub struct ActThree(
	pub(super) [u8; 66]
);

pub enum Act {
	One(ActOne),
	Two(ActTwo),
	Three(ActThree),
}

impl Act {
	pub fn serialize(&self) -> Vec<u8> {
		match self {
			Act::One(act) => {
				act.0.to_vec()
			}
			Act::Two(act) => {
				act.0.to_vec()
			}
			Act::Three(act) => {
				act.0.to_vec()
			}
		}
	}
}