pub trait Bool {}

#[derive(Copy, Clone)]
pub struct True {}

#[derive(Copy, Clone)]
pub struct False {}

impl Bool for True {}
impl Bool for False {}
