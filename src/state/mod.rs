pub mod error;


use crate::state::error::StateDatabaseError;
pub type StateIter = dyn Iterator<Item = Result<(String, Vec<u8>), StateDatabaseError>>;

pub trait StateReader: Send + Sync {
    /// Returns true if the given address exists in State; false, otherwise.
    ///
    /// Will return a StateDatabaseError if any errors occur while querying for
    /// the existence of the given address.
    fn contains(&self, address: &str) -> Result<bool, StateDatabaseError>;

    /// Returns the data for a given address, if it exists.  In the case where
    /// the address exists, but has no data, it will return None.
    ///
    /// Will return an StateDatabaseError::NotFound, if the given address is not
    /// in State.
    fn get(&self, address: &str) -> Result<Option<Vec<u8>>, StateDatabaseError>;

    /// A state value is considered a leaf if it has data stored at the address.
    ///
    /// Returns an iterator over address-value pairs in state.
    ///
    /// Returns Err if the prefix is invalid, or if any other database errors
    /// occur while creating the iterator.
    fn leaves(&self, prefix: Option<&str>) -> Result<Box<StateIter>, StateDatabaseError>;
}
