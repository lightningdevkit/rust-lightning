pub const ACT_ONE_LENGTH: usize = 50;
pub const ACT_TWO_LENGTH: usize = 50;
pub const ACT_THREE_LENGTH: usize = 66;

/// Wrapper for the first act message
pub struct ActOne(
	pub(super) [u8; ACT_ONE_LENGTH]
);

/// Wrapper for the second act message
pub struct ActTwo(
	pub(super) [u8; ACT_TWO_LENGTH]
);

/// Wrapper for the third act message
pub struct ActThree(
	pub(super) [u8; ACT_THREE_LENGTH]
);

/// Wrapper for any act message
pub enum Act {
	One(ActOne),
	Two(ActTwo),
	Three(ActThree),
}

impl Act {
	/// Convert any act into a byte vector
	pub fn serialize(&self) -> Vec<u8> {
		match self {
			&Act::One(ref act) => {
				act.0.to_vec()
			}
			&Act::Two(ref act) => {
				act.0.to_vec()
			}
			&Act::Three(ref act) => {
				act.0.to_vec()
			}
		}
	}
}