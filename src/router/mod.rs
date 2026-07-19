pub mod zte_f670l;

use crate::model::{BlockedDevice, Device, MacFilterStatus};
use anyhow::Result;

#[derive(Debug, Clone, Default)]
pub struct RouterCaps {
    pub per_host_traffic: bool,
    pub can_block: bool,
    pub message: String,
}

pub trait RouterBackend: Send {
    fn name(&self) -> &str;
    fn login(&mut self) -> Result<()>;
    fn list_devices(&mut self) -> Result<Vec<Device>>;
    fn list_blocked(&mut self) -> Result<Vec<BlockedDevice>>;
    fn mac_filter_status(&mut self) -> Result<MacFilterStatus>;
    /// Block a device by MAC via router firewall MAC filter.
    fn block_device(&mut self, mac: &str, name: &str) -> Result<()>;
    /// Remove a block rule by router instance id.
    fn unblock_device(&mut self, inst_id: &str) -> Result<()>;
    fn capabilities(&self) -> RouterCaps;
    fn is_logged_in(&self) -> bool;
}
