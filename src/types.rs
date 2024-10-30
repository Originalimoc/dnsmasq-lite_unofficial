pub mod time {
	pub type Ttl = chrono::TimeDelta;
	pub type Instant = chrono::DateTime<chrono::Utc>;
	pub fn now() -> Instant {
		chrono::Utc::now()
	}
}
