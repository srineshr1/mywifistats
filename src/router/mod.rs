pub mod zte_f670l;

use crate::model::Device;
use anyhow::Result;

#[derive(Debug, Clone, Default)]
pub struct RouterCaps {
    pub per_host_traffic: bool,
    pub message: String,
}

pub trait RouterBackend: Send {
    fn name(&self) -> &str;
    fn login(&mut self) -> Result<()>;
    fn list_devices(&mut self) -> Result<Vec<Device>>;
    fn capabilities(&self) -> RouterCaps;
    fn is_logged_in(&self) -> bool;
}
